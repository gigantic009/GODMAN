import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from jarvis.markets import sma, ema, rsi, bollinger_bands, macd, market_snapshot, detect_price_events


class MarketAnalyticsTests(unittest.TestCase):
    def test_averages(self):
        self.assertEqual(sma([1,2,3,4], 2), [1.5,2.5,3.5])
        self.assertEqual(len(ema([1,2,3,4], 2)), 3)

    def test_rsi(self):
        values = rsi(list(range(1,20)), 5)
        self.assertTrue(all(0 <= x <= 100 for x in values))
        self.assertEqual(values[-1], 100)

    def test_bands_and_macd(self):
        prices = [100+i*0.7+(i%4) for i in range(40)]
        self.assertEqual(len(bollinger_bands(prices, 10)), 31)
        self.assertTrue(macd(prices))
        falling = [200-i*1.3 for i in range(40)]
        self.assertTrue(macd(falling))

    def test_price_events(self):
        events = detect_price_events([100,105,98], 0.04)
        self.assertEqual([x["direction"] for x in events], ["up","down"])

    def test_snapshot(self):
        result = market_snapshot([100+i for i in range(60)])
        self.assertEqual(result["trend_observation"], "short_average_above_long")
        self.assertIn("not a forecast", result["interpretation"])

    def test_invalid_inputs(self):
        with self.assertRaises(ValueError): sma([1,2], 3)
        with self.assertRaises(ValueError): detect_price_events([1,2], 1.5)


if __name__ == "__main__":
    unittest.main()
