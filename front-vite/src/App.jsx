import { useState } from 'react';

function App() {
  const [url, setUrl] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleScan = async () => {
    if (!url) return alert("Please enter a URL");
    setLoading(true);
    try {
      const res = await fetch("http://localhost:5000/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      const data = await res.json();
      setResult(data);
    } catch (err) {
      alert("Failed to scan site.");
    }
    setLoading(false);
  };

  const handleDownload = () => {
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = "websafe_report.json";
    link.click();
  };

  return (
    <div style={{ padding: 20, width: 300 }}>
      <h2>🔐 WebSafe Sentinel</h2>
      <input
        type="text"
        placeholder="Enter website URL"
        value={url}
        onChange={(e) => setUrl(e.target.value)}
        style={{ width: "100%", padding: 6, marginBottom: 10 }}
      />
      <button onClick={handleScan} style={{ width: "100%", padding: 6 }}>
        {loading ? "Scanning..." : "Scan"}
      </button>

      {result && (
        <div style={{ marginTop: 10 }}>
          <p><strong>Status:</strong> Scan completed ✅</p>
          <p><strong>Issues:</strong> {Object.values(result).filter(Boolean).length}</p>
          <button onClick={handleDownload} style={{ marginTop: 8, padding: 6, width: "100%" }}>
            Download Full Report
          </button>
        </div>
      )}
    </div>
  );
}

export default App;
