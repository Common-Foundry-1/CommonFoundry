import { useEffect, useState } from "react";
import { DISCORD_URL, MAINNET_LAUNCH_AT, SOURCE_RELEASE_AT } from "../content";

const launchTime = Date.parse(MAINNET_LAUNCH_AT);

function remainingTime(now: number) {
  const totalSeconds = Math.max(0, Math.ceil((launchTime - now) / 1000));

  return {
    days: Math.floor(totalSeconds / 86_400),
    hours: Math.floor((totalSeconds % 86_400) / 3_600),
    minutes: Math.floor((totalSeconds % 3_600) / 60),
    seconds: totalSeconds % 60,
    hasStarted: totalSeconds === 0,
  };
}

export function MainnetCountdown() {
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    const interval = window.setInterval(() => setNow(Date.now()), 1_000);
    return () => window.clearInterval(interval);
  }, []);

  const remaining = remainingTime(now);

  return (
    <div className="mainnet-countdown" aria-labelledby="mainnet-countdown-heading">
      <div className="mainnet-countdown__intro">
        <span className="mainnet-countdown__eyebrow">The next chapter starts soon</span>
        <h2 id="mainnet-countdown-heading">Mainnet mining begins in</h2>
        <p>
          <time dateTime={MAINNET_LAUNCH_AT}>October 3, 2026 · Noon CDT / 17:00 UTC</time>
        </p>
        <p className="mainnet-countdown__source">
          Source and launch packages released <time dateTime={SOURCE_RELEASE_AT}>October 2 at noon CDT</time>.
        </p>
      </div>

      {remaining.hasStarted ? (
        <p className="mainnet-countdown__reached" role="status">
          Scheduled start time reached. <a href={DISCORD_URL} target="_blank" rel="noopener noreferrer">Check the official launch status in Discord.</a>
        </p>
      ) : (
        <div className="mainnet-countdown__clock" role="timer" aria-live="off" aria-label={`${remaining.days} days, ${remaining.hours} hours, ${remaining.minutes} minutes, ${remaining.seconds} seconds remaining`}>
          {([
            [remaining.days, "Days"],
            [remaining.hours, "Hours"],
            [remaining.minutes, "Minutes"],
            [remaining.seconds, "Seconds"],
          ] as const).map(([value, label]) => (
            <div className="mainnet-countdown__unit" key={label} aria-hidden="true">
              <strong>{String(value).padStart(2, "0")}</strong>
              <span>{label}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
