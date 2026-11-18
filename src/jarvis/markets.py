"""Deterministic market analytics over supplied chronological price observations."""
from statistics import mean, pstdev
from math import isfinite


def _series(values, minimum=1):
    if not isinstance(values, (list, tuple)) or len(values) < minimum:
        raise ValueError(f"Need at least {minimum} observations.")
    result = [float(x) for x in values]
    if any(x <= 0 for x in result):
        raise ValueError("Prices must be positive.")
    return result


def sma(prices, period):
    if period < 1:
        raise ValueError("period must be positive.")
    v = _series(prices, period)
    return [mean(v[i-period+1:i+1]) for i in range(period-1, len(v))]


def ema(prices, period):
    if period < 1:
        raise ValueError("period must be positive.")
    if not isinstance(prices, (list, tuple)) or len(prices) < period:
        raise ValueError(f"Need at least {period} observations.")
    v = [float(x) for x in prices]
    if any(not isfinite(x) for x in v):
        raise ValueError("Values must be finite.")
    alpha = 2 / (period + 1)
    current = mean(v[:period])
    out = [current]
    for price in v[period:]:
        current = alpha * price + (1-alpha) * current
        out.append(current)
    return out


def rsi(prices, period=14):
    v = _series(prices, period + 1)
    changes = [v[i] - v[i-1] for i in range(1, len(v))]
    gains = [max(x, 0.0) for x in changes]
    losses = [max(-x, 0.0) for x in changes]
    avg_gain, avg_loss = mean(gains[:period]), mean(losses[:period])
    out = []
    for i in range(period, len(changes)+1):
        if i > period:
            avg_gain = ((period-1)*avg_gain + gains[i-1]) / period
            avg_loss = ((period-1)*avg_loss + losses[i-1]) / period
        out.append(100.0 if avg_loss == 0 else 100 - 100/(1 + avg_gain/avg_loss))
    return out


def bollinger_bands(prices, period=20, deviations=2.0):
    if period < 2 or deviations <= 0:
        raise ValueError("period must be >= 2 and deviations positive.")
    v = _series(prices, period)
    out = []
    for end in range(period, len(v)+1):
        window = v[end-period:end]
        middle, sd = mean(window), pstdev(window)
        out.append({"middle": middle, "upper": middle+deviations*sd,
                    "lower": middle-deviations*sd})
    return out


def macd(prices, fast=12, slow=26, signal=9):
    if not (0 < fast < slow and signal > 0):
        raise ValueError("Require 0 < fast < slow and signal > 0.")
    v = _series(prices, slow+signal)
    fast_line, slow_line = ema(v, fast), ema(v, slow)
    offset = slow-fast
    line = [fast_line[i+offset]-slow_line[i] for i in range(len(slow_line))]
    signal_line = ema(line, signal)
    aligned = line[-len(signal_line):]
    return [{"macd": x, "signal": y, "histogram": x-y}
            for x, y in zip(aligned, signal_line)]


def market_snapshot(closes, rsi_period=14, short_window=20, long_window=50):
    v = _series(closes, max(rsi_period+1, short_window, long_window))
    short, long = sma(v, short_window)[-1], sma(v, long_window)[-1]
    returns = [v[i]/v[i-1]-1 for i in range(1, len(v))]
    peak, drawdown = v[0], 0.0
    for price in v:
        peak = max(peak, price)
        drawdown = min(drawdown, price/peak-1)
    return {
        "latest_close": v[-1], "sma_short": short, "sma_long": long,
        "trend_observation": "short_average_above_long" if short > long else
            "short_average_below_long" if short < long else "averages_equal",
        "rsi": rsi(v, rsi_period)[-1],
        "daily_return_volatility": pstdev(returns) if len(returns)>1 else 0.0,
        "max_observed_drawdown": abs(drawdown), "observations": len(v),
        "interpretation": "Historical descriptive indicators only; not a forecast or buy/sell recommendation."
    }


def detect_price_events(closes, move_threshold=0.03):
    if not 0 < move_threshold < 1:
        raise ValueError("move_threshold must be between 0 and 1.")
    v = _series(closes, 2)
    out = []
    for i in range(1, len(v)):
        change = v[i]/v[i-1]-1
        if abs(change) >= move_threshold:
            out.append({"observation_index": i, "previous_close": v[i-1],
                        "close": v[i], "return": change,
                        "direction": "up" if change > 0 else "down",
                        "threshold": move_threshold})
    return out
