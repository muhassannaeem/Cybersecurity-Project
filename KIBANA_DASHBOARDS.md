

# Required Kibana Dashboards & Charts (Based on Available Fields)

This section lists only the visualizations you can create with your current index pattern fields:

---

### 1. Service Health Dashboard
- **Log Count Over Time**
	- **Type:** Line Chart
	- **Index:** `cybersecurity-system-*`
	- **Time Range:** Last 1 hour
	- **X (Horizontal axis):** `@timestamp` (Date histogram)
	- **Y (Vertical axis):** Count of records
	- **Breakdown:** `container.name.keyword` (recommended)

---

### 2. Log Details & Error Monitoring Dashboard
- **Error Logs Over Time**
	- **Type:** Line Chart
	- **Index:** `cybersecurity-system-*`
	- **Time Range:** Last 1 hour
	- **Filter:** `message.keyword` contains "error" (use KQL: `message.keyword : "*error*"`)
	- **X (Horizontal axis):** `@timestamp` (Date histogram)
	- **Y (Vertical axis):** Count of records
	- **Breakdown:** `container.name.keyword` (optional)
- **Recent Error Table**
	- **Type:** Table
	- **Index:** `cybersecurity-system-*`
	- **Time Range:** Last 1 hour
	- **Filter:** `message.keyword` contains "error"
	- **Columns:** `@timestamp`, `container.name.keyword`, `message.keyword`, `log.file.path.keyword`

---

### 3. Log Message Distribution Dashboard
- **Log Message Distribution**
	- **Type:** Pie Chart
	- **Index:** `cybersecurity-system-*`
	- **Time Range:** Last 1 hour
	- **Slice:** `container.name.keyword` (shows distribution by container/service)
	- **Size:** Count of records

---

> **Note:**
> - Use the `Last 1 hour` time filter in Kibana for all visualizations.
> - Field names are based on your actual index pattern. Use the field browser in Kibana to confirm and explore more options.
> - For error logs, use KQL filter: `message.keyword : "*error*"`
> - For breakdowns, use `.keyword` fields for exact matches.
> - Adjust filters and breakdowns as needed for your data.
