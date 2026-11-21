"""Match the packaged SM8750 vCPU profile to the static boot ADT.

DroidVM/crosvm creates the real FDT at boot. The checked-in FDT is a reference
for building the OS's static ADT only; derive its CPU-dependent properties
from the same profile that will configure crosvm when the package is imported.
"""
import json
from pathlib import Path
import struct

GIC_DIST = 0x3fff0000
GIC_DIST_SIZE = 0x10000
GIC_REDIST_STRIDE = 0x20000
PPI_CPU_BITS = 0xff00


def profile_cpu_count(profile):
    vm = json.loads(Path(profile).read_text())['vm']
    count = vm['cpu_count']
    if type(count) is not int or not 2 <= count <= 8:
        raise ValueError('expected 2–8 recovery vCPUs')
    # Every vCPU may run on any of the eight host CPUs. Advertise the weakest
    # accessible host capacity, as droidvmd would with automatic topology.
    # droidvmd emits no --cpu-cluster for a single cluster.
    if (vm['backend'], vm['hypervisor']) != ('crosvm', 'gunyah') or vm['cpu_topology_auto'] is not False or vm['cpu_perf_requests'] is not False \
            or vm['cpu_affinity'] != ':'.join(f'{i}=0-7' for i in range(count)) \
            or vm['cpu_capacity'] != ','.join(f'{i}=792' for i in range(count)) \
            or vm['cpu_clusters'] != f'0-{count - 1}':
        raise ValueError('expected unpinned, uniform-capacity Gunyah recovery vCPUs')
    return count


def gic_reg(count):
    # crosvm aarch64/src/{lib,fdt}.rs: one redistributor frame per vCPU,
    # immediately below the distributor. Gunyah CPUIDs are Affinity0 indices.
    size = GIC_REDIST_STRIDE * count
    return GIC_DIST, GIC_DIST_SIZE, GIC_DIST - size, size


def retarget_fdt(fdt, count):
    cpus = {f'/cpus/cpu@{i:x}': i for i in range(8)}
    available = {path for path, node in fdt.items() if path.startswith('/cpus/') and node.get('device_type') == b'cpu\0'}
    gic = fdt['/intc']
    if (available != set(cpus) or any(fdt[path]['reg'] != struct.pack('>I', i) for path, i in cpus.items())
            or gic.get('compatible') != b'arm,gic-v3\0' or gic['reg'] != struct.pack('>4Q', *gic_reg(8))
            or '/cpufreq' in fdt):
        raise ValueError('reference tree no longer matches the eight-vCPU crosvm layout')
    for path, i in cpus.items():
        if i < count:
            fdt[path]['capacity-dmips-mhz'] = struct.pack('>I', 792)
        else:
            del fdt[path]
    for path in list(fdt):
        if path == '/cpus/cpu-map' or path.startswith('/cpus/cpu-map/'):
            del fdt[path]
    gic['reg'] = struct.pack('>4Q', *gic_reg(count))
    # The crosvm timer, PMU and watchdog advertise a PPI target mask for
    # all vCPUs. Keep the trigger flags and CPU-independent IRQs intact.
    for path, node in fdt.items():
        if path not in ('/timer', '/pmu') and not path.startswith('/vmwdt@'):
            continue
        irq = node['interrupts']
        irq_data = bytearray()
        for kind, number, flags in struct.iter_unpack('>III', irq):
            if kind != 1 or flags & PPI_CPU_BITS != PPI_CPU_BITS:
                raise ValueError(f'unexpected interrupt in {path}')
            irq_data.extend(struct.pack('>III', kind, number, flags & ~PPI_CPU_BITS | ((1 << count) - 1) << 8))
        node['interrupts'] = bytes(irq_data)
    return fdt


def adt_properties(data):
    """An Apple device tree as {path/property: value}."""
    result = {}

    def node(at, path):
        properties, children = struct.unpack_from('<II', data, at)
        at += 8
        own = {}
        for _ in range(properties):
            key = data[at:at + 32].split(b'\0')[0].decode()
            size = struct.unpack_from('<I', data, at + 32)[0] & 0x7fffffff
            value = data[at + 36:at + 36 + size]
            if len(value) != size or key in own:
                raise ValueError('truncated or duplicate ADT property')
            own[key] = value
            at += 36 + ((size + 3) & ~3)
        here = '/'.join(filter(None, (path, own['name'].rstrip(b'\0').decode())))
        result.update({f'{here}:{key}': value for key, value in own.items()})
        for _ in range(children):
            at = node(at, here)
        return at

    if node(0, '') != len(data):
        raise ValueError('unexpected data after ADT')
    return result


def verify_adt_cpu_profile(adt, profile):
    count = profile_cpu_count(profile)
    props = adt_properties(adt)
    cpu_regs = {path: value for path, value in props.items() if path.startswith('device-tree/cpus/') and path.endswith(':reg')}
    expected = {f'device-tree/cpus/cpu{i}:reg': struct.pack('<I', i) for i in range(count)}
    if cpu_regs != expected or any(props.get(path.removesuffix(':reg') + ':cluster-type') != b'P\0' for path in expected):
        raise ValueError('boot ADT vCPUs or cluster types do not match the recovery profile')
    # ADT arm-io ranges are <child address, parent address, length>.
    offset, armio_base, size = struct.unpack('<3Q', props['device-tree/arm-io:ranges'])
    dist, dist_size, redist, redist_size = gic_reg(count)
    if offset or not armio_base <= redist < dist + dist_size <= armio_base + size:
        raise ValueError('boot ADT arm-io range does not encompass the recovery GICv3 layout')
    if props['device-tree/arm-io/intc:reg'] != struct.pack('<4Q', dist - armio_base, dist_size, redist - armio_base, redist_size):
        raise ValueError('boot ADT GICv3 distributor/redistributor layout does not match the recovery profile')
    if props['device-tree/arm-io/intc:redistributor-stride'] != struct.pack('<Q', GIC_REDIST_STRIDE):
        raise ValueError('boot ADT redistributor stride does not match crosvm')
    return count
