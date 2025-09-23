"use client";
import { useCallback, useEffect, useRef, useState } from "react";

const MS_PER_DAY = 24 * 60 * 60 * 1000;
const UPDATE_INTERVAL = 10;
const ANIMATION_DURATION = 5000;

function calculateProgress() {
	const now = new Date();
	const curYear = now.getFullYear();

	const startY = new Date(curYear, 0, 1).getTime();
	const endY = new Date(curYear + 1, 0, 1).getTime();
	const yProg = ((now.getTime() - startY) / (endY - startY)) * 100;

	const startD = new Date(curYear, now.getMonth(), now.getDate()).getTime();
	const endD = new Date(curYear, now.getMonth(), now.getDate() + 1).getTime();
	const dProg = ((now.getTime() - startD) / (endD - startD)) * 100;

	const dayOfYear =
		Math.floor(
			(Date.UTC(curYear, now.getMonth(), now.getDate()) -
				Date.UTC(curYear, 0, 1)) /
				MS_PER_DAY,
		) + 1;

	const centuryStart = new Date(2000, 0, 1).getTime();
	const centuryEnd = new Date(2100, 0, 1).getTime();
	const centuryProg =
		((now.getTime() - centuryStart) / (centuryEnd - centuryStart)) * 100;

	return { yProg, dProg, dayOfYear, curYear, centuryProg, now };
}

function formatPercent(v) {
	return Number.isFinite(v) ? `${v.toFixed(5)}%` : "0.00000%";
}

export default function TimelineProgress() {
	const loveStartDate = null;

	const [yProg, setYProg] = useState(0);
	const [dProg, setDProg] = useState(0);
	const [dayOfYear, setDayOfYear] = useState(0);
	const [curYear, setCurYear] = useState(new Date().getFullYear());
	const [centuryProg, setCenturyProg] = useState(0);
	const [loveDays, setLoveDays] = useState(0);

	const animYProg = useRef(null);
	const animDProg = useRef(null);
	const animDayOfYear = useRef(null);
	const animCurYear = useRef(null);
	const animCenturyProg = useRef(null);
	const animLoveDays = useRef(null);

	const [, forceUpdate] = useState({});

	const animateValue = useCallback((ref, targetValue, duration, callback) => {
		const startValue = ref.current ?? 0;
		const startTime = performance.now();

		function step(time) {
			const elapsed = time - startTime;
			if (elapsed >= duration) {
				ref.current = targetValue;
				forceUpdate({});
				if (callback) callback();
				return;
			}
			const progress = elapsed / duration;
			ref.current = startValue + (targetValue - startValue) * progress;
			forceUpdate({});
			requestAnimationFrame(step);
		}

		requestAnimationFrame(step);
	}, []);

	useEffect(() => {
		const { yProg, dProg, dayOfYear, curYear, centuryProg, now } =
			calculateProgress();

		animateValue(animYProg, yProg, ANIMATION_DURATION, () => {
			animYProg.current = null;
		});
		animateValue(animDProg, dProg, ANIMATION_DURATION, () => {
			animDProg.current = null;
		});
		animateValue(animDayOfYear, dayOfYear, ANIMATION_DURATION, () => {
			animDayOfYear.current = null;
		});
		animateValue(animCurYear, curYear, ANIMATION_DURATION, () => {
			animCurYear.current = null;
		});
		animateValue(animCenturyProg, centuryProg, ANIMATION_DURATION, () => {
			animCenturyProg.current = null;
		});

		if (loveStartDate) {
			const loveDaysVal =
				(now.getTime() - loveStartDate.getTime()) / MS_PER_DAY;
			animateValue(animLoveDays, loveDaysVal, ANIMATION_DURATION, () => {
				animLoveDays.current = null;
			});
			setTimeout(() => setLoveDays(loveDaysVal), ANIMATION_DURATION);
		}

		setTimeout(() => {
			setYProg(yProg);
			setDProg(dProg);
			setDayOfYear(dayOfYear);
			setCurYear(curYear);
			setCenturyProg(centuryProg);
		}, ANIMATION_DURATION);

		const interval = setInterval(() => {
			const { yProg, dProg, dayOfYear, curYear, centuryProg, now } =
				calculateProgress();

			setYProg(yProg);
			setDProg(dProg);
			setDayOfYear(dayOfYear);
			setCurYear(curYear);
			setCenturyProg(centuryProg);

			if (loveStartDate) {
				const newLoveDays =
					(now.getTime() - loveStartDate.getTime()) / MS_PER_DAY;
				setLoveDays((prev) =>
					Math.abs(prev - newLoveDays) > 0.0001 ? newLoveDays : prev,
				);
			}
		}, UPDATE_INTERVAL);

		return () => clearInterval(interval);
	}, [animateValue]);

	const displayYProg = animYProg.current !== null ? animYProg.current : yProg;
	const displayDProg = animDProg.current !== null ? animDProg.current : dProg;
	const displayDayOfYear =
		animDayOfYear.current !== null ? animDayOfYear.current : dayOfYear;
	const displayCurYear =
		animCurYear.current !== null ? animCurYear.current : curYear;
	const displayCenturyProg =
		animCenturyProg.current !== null ? animCenturyProg.current : centuryProg;
	const displayLoveDays =
		animLoveDays.current !== null ? animLoveDays.current : loveDays;

	return (
		<>
			<ul>
				<li>
					Today is{" "}
					<span className="time-number">{Math.round(displayDayOfYear)}</span>{" "}
					day of{" "}
					<span className="time-number">{Math.round(displayCurYear)}</span>
				</li>
				<li>
					Century progress:{" "}
					<span className="time-number">
						{formatPercent(displayCenturyProg)}
					</span>
				</li>
				<li>
					Year progress:{" "}
					<span className="time-number">{formatPercent(displayYProg)}</span>
				</li>
				<li>
					Day progress:{" "}
					<span className="time-number">{formatPercent(displayDProg)}</span>
				</li>
				<hr />
				<center>
					{loveStartDate ? (
						<>
							<span className="time-number">{Math.floor(displayLoveDays)}</span>{" "}
							days painted softly on the canvas of 「时光」🎨
						</>
					) : (
						<span className="time-number">
							一场未曾落幕的梦，静待与君相逢 💫
						</span>
					)}
				</center>
			</ul>

			<style jsx>{`
        .time-number {
          display: inline-block;
          font-feature-settings: "tnum";
          font-variant-numeric: tabular-nums;
          font-weight: 600;
          color: var(--primary);
          min-width: 2.5em;
          text-align: center;
        }
      `}</style>
		</>
	);
}
