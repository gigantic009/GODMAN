# GODMAN Market Intelligence Division

## Mission
Build an independent research workstation inspired by professional equity research
and quantitative desks. This is an engineering ambition, not a claim of affiliation
with or equivalent performance to JPMorgan, Goldman Sachs, or another institution.

## Implemented foundation
`src/jarvis/markets.py` calculates SMA, EMA, RSI, MACD, Bollinger Bands, historical
return volatility, maximum observed drawdown, and configurable price-move events
from supplied chronological closing prices. It does not fetch quotes, identify
securities, understand exchange calendars, or place trades. Tests use synthetic data.

## What institutional-quality research requires
1. Reliable licensed market data with exchange timestamps, live/delayed labels, OHLCV,
   corporate actions, fundamentals, filings, estimates, macro data, and news.
2. Financial statement normalization, valuation, scenario analysis, earnings quality,
   peer analysis, factor models, event studies, and portfolio risk.
3. Walk-forward/out-of-sample testing, transaction costs, slippage, liquidity,
   survivorship-bias and look-ahead-bias controls.
4. User-defined watchlists, market-session awareness, threshold/anomaly alerts,
   stale-feed detection, and auditable event history.
5. Timestamped research with source citations, bull/base/bear cases, catalysts, risks,
   sensitivities, and explicit uncertainty.

## Market monitoring data contract
A future provider adapter must normalize instrument, exchange, currency, timezone,
event timestamp, ingestion timestamp, OHLCV, adjusted/unadjusted status, provider,
entitlement, and real-time/delayed classification. Alerts should be configurable
descriptive observations—not predictions or trade instructions.

## Research discipline
Prefer company filings, exchange disclosures, regulator publications, and primary
macroeconomic sources. Separate facts, estimates, assumptions, and model outputs.
Show formulas, inputs, time windows, gaps, and limitations. Never fabricate prices,
news, financials, holdings, or consensus data. Do not connect a brokerage in this phase.
JPMorgan/Goldman Sachs are quality benchmarks for analytical discipline only; GODMAN
is independent and has no affiliation with them.

See [ROADMAP.md](ROADMAP.md).
