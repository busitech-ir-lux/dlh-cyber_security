DROP TABLE IF EXISTS patient_orders;

CREATE TABLE patient_orders (
  order_id INTEGER PRIMARY KEY AUTOINCREMENT,
  patient_mrn TEXT NOT NULL,
  test_code TEXT NOT NULL,
  ordered_at TEXT DEFAULT CURRENT_TIMESTAMP,
  status TEXT DEFAULT 'PENDING',
  result_value TEXT,
  critical_flag INTEGER DEFAULT 0
);

INSERT INTO patient_orders
  (patient_mrn, test_code, status, result_value, critical_flag)
VALUES
  ('MRN-10042', 'CBC', 'RESULTED', '9.2/13.4/412', 0),
  ('MRN-10043', 'BMP', 'RESULTED', 'K+: 6.1 mEq/L', 1),
  ('MRN-10044', 'PT-INR', 'PENDING', NULL, 0),
  ('MRN-10045', 'TROPONIN', 'RESULTED', '0.08 ng/mL', 1),
  ('MRN-10046', 'LACTATE', 'PENDING', NULL, 0);