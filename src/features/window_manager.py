import collections
from datetime import datetime, timedelta

class LiveFeatureWindow:
    def __init__(self, window_minutes=5):
        self.window_duration = timedelta(minutes=window_minutes)
        # Store events as a list of tuples: (timestamp, status)
        self.history = collections.defaultdict(list)

    def add_event(self, src_ip: str, user: str, status: str):
        now = datetime.now()
        key = (src_ip, user)
        self.history[key].append((now, status))
        self._clean_old_events(now)

    def _clean_old_events(self, now: datetime):
        """Removes logs older than the sliding window timeframe (e.g., 5 mins)."""
        for key in list(self.history.keys()):
            self.history[key] = [
                event for event in self.history[key]
                if now - event[0] <= self.window_duration
            ]
            if not self.history[key]:
                del self.history[key]

    def get_features(self, src_ip: str, user: str):
        """Calculates features dynamically for a specific IP-User pair."""
        events = self.history.get((src_ip, user), [])
        failures = sum(1 for _, status in events if status == "failure")
        successes = sum(1 for _, status in events if status == "success")
        total = failures + successes
       
        failure_rate = failures / total if total > 0 else 0.0

        # Calculate unique users targeted by this specific IP across the entire window
        unique_users = len({
            k[1] for k in self.history.keys()
            if k[0] == src_ip
        })

        return {
            "failures": failures,
            "successes": successes,
            "failure_rate": failure_rate,
            "unique_users": unique_users
        }
