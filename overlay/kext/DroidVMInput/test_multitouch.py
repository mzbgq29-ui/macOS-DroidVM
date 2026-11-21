#!/usr/bin/env python3
"""Run evdev touch traces through the driver's real event/multitouch methods.

This host-only harness substitutes IOKit report delivery, not the state machine.
It checks emitted Apple path stages and positions; it does not emulate WindowServer
or claim that a real macOS/Android input session has been tested.
"""
from pathlib import Path
import argparse
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--source', type=Path, default=Path(__file__).with_name('DroidVMInput.cpp'))
args = parser.parse_args()
source = args.source.read_text()

def method(name):
    start = source.index('void DroidVMInput::' + name + '(')
    end = source.index('\n}\n', start) + 3
    return source[start:end]

# Take the production slot/state declarations so changes to their representation
# are compiled into this fixture as well as the two production methods below.
state = source[source.index('  Kind kind = Kind::none;'):source.index('  DroidVMHIDDevice *hid = nullptr;')]
# Select the wire event constants and device kinds, without IOKit configuration constants.
enums = source[source.index('enum : uint16_t { evSyn'):source.index('constexpr unsigned maxDevices')]
identify = source[source.index('unsigned configBytes('):source.index('IOBufferMemoryDescriptor *contiguous(')]
kind_name = source[source.index('const char *kindName('):source.index('}  // namespace\n\nbool DroidVMInput::start(')]
mt = source[source.index('namespace mt {'):source.index('// A feature report', source.index('namespace mt {'))]
scale = source[source.index('int32_t scale('):source.index('OSDictionary *multitouchProperties(')]
program = r'''
#include <array>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <vector>
constexpr unsigned maxSlots = 10, fingers = 4;
constexpr int32_t tabletRange = 0x8000;
constexpr int kIODirectionNone = 0;
bool gTouchTablet = false;
template<class... A> void IOLog(const char *, A...) {}
uint64_t mach_absolute_time() { static uint64_t now = 0; return now += 1000000; }
void absolutetime_to_nanoseconds(uint64_t value, uint64_t *out) { *out = value; }
struct IOBufferMemoryDescriptor {
  std::vector<uint8_t> bytes;
  static IOBufferMemoryDescriptor *withBytes(const uint8_t *data, unsigned length, int) {
    return new IOBufferMemoryDescriptor{{data, data + length}};
  }
  void release() { delete this; }
};
struct DroidVMHIDDevice {
  std::vector<std::vector<uint8_t>> wire;
  void handleReport(IOBufferMemoryDescriptor *report) { wire.push_back(report->bytes); }
};
''' + enums + '\n' + mt + '}\n' + scale + r'''
struct Event { uint16_t type, code; int32_t value; };
uint8_t linuxToHid[256] = {};
struct DeviceConfig {
  uint8_t select = 0, subsel = 0;
  uint8_t properties = 0;
  bool slots = true;
  template<typename T> void setConfig(unsigned offset, T value) {
    if (offset == cfgSelect) select = value;
    if (offset == cfgSubsel) subsel = value;
  }
  template<typename T> T config(unsigned offset) const {
    uint8_t bytes[20] = {};
    unsigned size = 0;
    if (select == cfgPropBits) { bytes[0] = properties; size = 1; }
    if (select == cfgEvBits && subsel == evAbs) {
      const unsigned axes[] = {absMtSlot, absMtPositionX, absMtPositionY};
      for (unsigned index : axes)
        if (index != absMtSlot || slots)
          bytes[index / 8] |= 1 << (index % 8);
      size = 8;
    }
    if (select == cfgAbsInfo && (subsel == absMtPositionX || subsel == absMtPositionY)) {
      bytes[4] = 0xff; bytes[5] = 0x7f;
      size = sizeof(bytes);
    }
    return offset == cfgSize ? size : offset >= cfgData && offset-cfgData < size ? bytes[offset-cfgData] : 0;
  }
};
struct DroidVMInputDevice {
  DeviceConfig transport;
''' + state + r'''
  DroidVMHIDDevice *hid = nullptr;
};
struct Snapshot {
  std::array<uint8_t, maxSlots> stage;
  std::array<int32_t, maxSlots> x, y;
};
class DroidVMInput {
public:
  std::vector<Snapshot> frames;
  unsigned wakes = 0;
  void event(DroidVMInputDevice &, const Event &);
  void multitouch(DroidVMInputDevice &);
  void report(DroidVMInputDevice &d);
  void userActive() { ++wakes; }
  void recordTime(DroidVMInputDevice &) {}
  void serializePathFrame(DroidVMInputDevice &, const uint8_t *);
  void pathFrame(DroidVMInputDevice &d, const uint8_t *stages) {
    Snapshot frame{};
    for (unsigned i = 0; i < maxSlots; ++i) {
      frame.stage[i] = stages[i];
      frame.x[i] = d.sent[i].x;
      frame.y[i] = d.sent[i].y;
    }
    frames.push_back(frame);
    serializePathFrame(d, stages);
  }
};
''' + identify + kind_name + method('event') + method('report') + method('multitouch') + method('pathFrame').replace('DroidVMInput::pathFrame(', 'DroidVMInput::serializePathFrame(', 1) + r'''
void abs(DroidVMInput &input, DroidVMInputDevice &d, uint16_t code, int value) {
  input.event(d, {evAbs, code, value});
}
void sync(DroidVMInput &input, DroidVMInputDevice &d) {
  input.event(d, {evSyn, synReport, 0});
}
void down(DroidVMInput &input, DroidVMInputDevice &d, int slot, int id, int x, int y) {
  abs(input, d, absMtSlot, slot);
  abs(input, d, absMtTrackingId, id);
  abs(input, d, absMtPositionX, x);
  abs(input, d, absMtPositionY, y);
}
void expectReplacement(bool reuseSameId, bool liftOtherFinger) {
  DroidVMInput input;
  DroidVMInputDevice d;
  DroidVMHIDDevice hid;
  d.hid = &hid;
  d.spanX = d.spanY = 32768;
  d.kind = Kind::touch;
  down(input, d, 0, 21, 100, 200);
  down(input, d, 1, 22, 800, 900);
  sync(input, d);
  input.frames.clear();
  hid.wire.clear();
  abs(input, d, absMtSlot, 0);
  if (reuseSameId) abs(input, d, absMtTrackingId, -1);
  down(input, d, 0, reuseSameId ? 21 : 23, 300, 400);
  if (liftOtherFinger) {
    abs(input, d, absMtSlot, 1);
    abs(input, d, absMtTrackingId, -1);
  }
  sync(input, d);
  assert(input.frames.size() == 4);
  const uint8_t stages[] = {mt::breakTouch, mt::outOfRange, mt::startInRange, mt::makeTouch};
  for (unsigned i = 0; i < 4; ++i) {
    const auto &f = input.frames[i];
    assert(f.stage[0] == stages[i]);
    assert(f.x[0] == (i < 2 ? 100 : 300));
    assert(f.y[0] == (i < 2 ? 200 : 400));
    const uint8_t otherStage = liftOtherFinger ? (i < 2 ? stages[i] : 0) : mt::touching;
    assert(f.stage[1] == otherStage && f.x[1] == 800 && f.y[1] == 900);
    const auto &wire = hid.wire[i];
    const unsigned paths = otherStage ? 2 : 1;
    assert(wire.size() == mt::headerSize + paths * mt::pathSize);
    assert(wire[0] == mt::pathFrame && wire[16] == paths && wire[17] == mt::pathSize);
    assert(wire[25] == 1 && wire[26] == stages[i]); // stable Apple path ID for slot 0
    if (otherStage) assert(wire[55] == 2 && wire[56] == otherStage);
    const int x = wire[29] | (wire[30] << 8);
    const int y = wire[31] | (wire[32] << 8);
    const int expectedX = (i < 2 ? 100 : 300) * mt::width / 32767;
    const int expectedY = mt::height - (i < 2 ? 200 : 400) * mt::height / 32767;
    assert(x == expectedX && y == expectedY);
  }
  assert(input.wakes == 2);
  input.frames.clear();
  sync(input, d);
  assert(input.frames.size() == 1 && input.frames[0].stage[0] == mt::touching);
}
void expectPointerTap(Kind kind, bool touchTablet) {
  DroidVMInput input;
  DroidVMInputDevice d;
  DroidVMHIDDevice hid;
  gTouchTablet = touchTablet;
  d.hid = &hid;
  d.kind = kind;
  d.spanX = d.spanY = 32768;
  down(input, d, 0, 33, 0x1234, 0x5678);
  sync(input, d);
  assert(input.frames.empty());
  assert((hid.wire == std::vector<std::vector<uint8_t>>{{1, 0x34, 0x12, 0x78, 0x56, 0}}));
  sync(input, d); // stationary keepalive must not double-click
  assert(hid.wire.size() == 1);
  abs(input, d, absMtTrackingId, -1);
  sync(input, d);
  assert(hid.wire.size() == 2);
  assert((hid.wire.back() == std::vector<uint8_t>{0, 0x34, 0x12, 0x78, 0x56, 0}));
  gTouchTablet = false;
}
void expectDistinctInputRoles() {
  DroidVMInputDevice d;
  d.transport.properties = 1 << inputPropDirect;
  assert(identify(d) == Kind::touch);
  assert(d.minX == 0 && d.spanX == 32768);
  d.transport.properties = 1 << inputPropPointer;
  assert(identify(d) == Kind::touchpad);
  d.transport.properties = 0;
  assert(identify(d) == Kind::touch); // older emulated screens without property bits
  d.transport.slots = false;
  assert(identify(d) == Kind::none); // cannot decode a type-A device as type B
}
int main() {
  expectDistinctInputRoles();
  expectPointerTap(Kind::touchpad, false);
  expectPointerTap(Kind::touch, true);
  DroidVMInput input;
  DroidVMInputDevice d;
  DroidVMHIDDevice hid;
  d.hid = &hid;
  d.spanX = d.spanY = 32768;
  d.kind = Kind::touch;
  sync(input, d);
  assert(input.frames.empty());
  down(input, d, 0, 11, 100, 200);
  sync(input, d);
  assert(input.frames.size() == 2);
  assert(input.frames[0].stage[0] == mt::startInRange);
  assert(input.frames[1].stage[0] == mt::makeTouch);
  assert(input.wakes == 1);
  input.frames.clear();
  // Stationary host scan frames must remain observable to the guest consumer.
  abs(input, d, absMtPositionX, 100);
  abs(input, d, absMtPositionY, 200);
  sync(input, d);
  assert(input.frames.size() == 1 && input.frames[0].stage[0] == mt::touching);
  assert(input.wakes == 1);
  input.frames.clear();
  down(input, d, 1, 12, 600, 700);
  sync(input, d);
  assert(input.frames.size() == 2 && input.frames[0].stage[0] == mt::touching);
  assert(input.frames[1].stage[1] == mt::makeTouch);
  input.frames.clear();
  // Android ACTION_CANCEL releases every active slot in one SYN frame.
  abs(input, d, absMtSlot, 0);
  abs(input, d, absMtTrackingId, -1);
  abs(input, d, absMtSlot, 1);
  abs(input, d, absMtTrackingId, -1);
  sync(input, d);
  assert(input.frames.size() == 2);
  for (unsigned slot = 0; slot < 2; ++slot) {
    assert(input.frames[0].stage[slot] == mt::breakTouch);
    assert(input.frames[1].stage[slot] == mt::outOfRange);
  }
  input.frames.clear();
  sync(input, d);
  assert(input.frames.empty());
  // Out-of-range slots cannot replace a live slot by accident.
  abs(input, d, absMtSlot, 10);
  abs(input, d, absMtTrackingId, 500);
  sync(input, d);
  assert(input.frames.empty());
  expectReplacement(false, false);
  expectReplacement(true, false);
  expectReplacement(false, true);
  std::cout << "PASS: device roles, pointer taps, landing, stationary scan, cancellation, idle, invalid slot, tracking-ID replacement, same-ID reuse, concurrent lift\n";
}
'''
with tempfile.TemporaryDirectory(prefix='droidvm-touch-') as tmp:
    cpp = Path(tmp) / 'touch.cpp'
    executable = Path(tmp) / 'touch-test'
    cpp.write_text(program)
    subprocess.run(['c++', '-std=c++17', '-Wall', '-Wextra', '-Werror', '-pedantic', str(cpp), '-o', str(executable)], check=True)
    subprocess.run([str(executable)], check=True)
