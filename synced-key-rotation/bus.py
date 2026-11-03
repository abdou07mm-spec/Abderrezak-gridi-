"""
الحافلة (حركة غطاء)
===================
حزمة تنطلق في مواعيد عشوائية، بمعدل حزمة كل 5 دقائق تقريبًا (بين 2.5 و7.5
دقيقة)، سواء كان فيها "ركاب" (رسائل حقيقية) أم لا (حزمة وهمية).

- الرسالة الحقيقية لا تنطلق فورًا: تنتظر في الطابور حتى الحافلة التالية.
  وإذا كانت عدة رسائل قصيرة في الانتظار، تركب الحافلة نفسها معًا.
- مواعيد الانطلاق مستقلة تمامًا عن نشاطك: المراقب يرى التدفق نفسه دائمًا،
  تكلمتما أو صمتّما.
- كل حزمة، حقيقية أو وهمية، تحمل نصفًا عشوائيًا جديدًا بعد كل استقبال
  (السقّاطة في online_node.py)، فتتجدد المفاتيح كل بضع دقائق حتى في الصمت.
- عند التغيير السري للفترة، تركب المصافحة الحافلة أيضًا (بدل حزمة وهمية)
  حتى يؤكد الطرف الآخر استلامها؛ فلا تظهر لحظة التغيير للمراقب.
- إذا لم يتوفر أي مفتاح (مثلًا قبل استيراد مفتاح الفترة الجديدة)، تنطلق
  حزمة من ضجيج عشوائي بالشكل نفسه، كي لا تظهر فجوة في المواعيد.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from common import secure_random, to_utc
from online_node import (
    MAX_TEXT_BYTES,
    KeyUnavailable,
    NodeError,
    OnlineNode,
    passengers_fit,
    random_filler,
)

MIN_GAP = timedelta(minutes=2.5)
MAX_GAP = timedelta(minutes=7.5)     # المتوسط 5 دقائق


def random_gap() -> timedelta:
    """مدة عشوائية حتى الانطلاق التالي (من مولّد مفحوص)."""
    fraction = int.from_bytes(secure_random(16)[:8], "big") / 2 ** 64
    return MIN_GAP + (MAX_GAP - MIN_GAP) * fraction


@dataclass
class Departure:
    time: datetime
    packet: str
    kind: str          # "message" أو "dummy" أو "handshake" أو "noise" (يعرفه المرسل وحده)
    riders: int = 0    # عدد الرسائل الحقيقية في الحزمة


@dataclass
class Bus:
    node: OnlineNode
    next_departure: datetime
    queue: list[tuple[datetime, str]] = field(default_factory=list)   # (وقت الكتابة، النص)
    waits: list[timedelta] = field(default_factory=list)              # كم انتظرت كل رسالة

    @classmethod
    def start(cls, node: OnlineNode, now: datetime) -> "Bus":
        return cls(node, to_utc(now) + random_gap())

    def enqueue(self, text: str, now: datetime) -> None:
        if len(text.encode("utf-8")) > MAX_TEXT_BYTES:
            raise NodeError(f"النص أطول من الحد المسموح ({MAX_TEXT_BYTES} بايت)")
        self.queue.append((to_utc(now), text))

    def departures_until(self, now: datetime) -> list[Departure]:
        """كل الحافلات التي حان موعدها حتى اللحظة now."""
        departures = []
        while self.next_departure <= to_utc(now):
            departures.append(self._depart(self.next_departure))
            self.next_departure += random_gap()
        return departures

    def _depart(self, moment: datetime) -> Departure:
        try:
            _, state = self.node.current_state(moment)
        except KeyUnavailable:
            return Departure(moment, random_filler(), "noise")
        if not state.ready or not state.peer_confirmed:
            return Departure(moment, self.node.my_handshake(moment), "handshake")
        riders: list[tuple[datetime, str]] = []
        while self.queue and passengers_fit([t for _, t in riders] + [self.queue[0][1]]):
            riders.append(self.queue.pop(0))
        try:
            packet = self.node.seal_packet([text for _, text in riders], moment)
        except KeyUnavailable:
            self.queue[:0] = riders            # الركاب ينتظرون الحافلة التالية
            return Departure(moment, random_filler(), "noise")
        self.waits.extend(moment - written for written, _ in riders)
        return Departure(moment, packet, "message" if riders else "dummy", len(riders))
