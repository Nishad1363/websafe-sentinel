import { useState, useEffect } from 'react';
import './App.css';

function App() {
  const [url, setUrl] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [reportUrl, setReportUrl] = useState('');
  const handleScan = async () => {
    if (!url) {
      setError("Please enter a URL");
      return;
    }
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await fetch("/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({url:url }),
      });
      if (!res.ok) {
        const text = await res.text(); // Log the raw response
        console.error("Server response:", text);
        throw new Error(`HTTP error! Status: ${res.status}, Response: ${text}`);
      }
      const data = await res.json();
      setResult(data);
      console.log("Triggerflow is called with input ",data);
      triggerFlow(data);
      console.log(result);
    } catch (err) {
      setError(`Failed to scan site: ${err.message}`);
      console.error("Fetch error:", err);
    }
    setLoading(false);
  };
  // async function triggerFlow() {
  //   const apiKey = 'wh_m98i5sr8Dh2c0W7fj3t8z8E13mKs8l5xfPtiNAhm';
  //   try {
  //     const response = await fetch('https://api.worqhat.com/flows/trigger/76135102-bc2e-4bd3-a1a8-7e41477dd5aa', {
  //       method: 'POST',
  //       headers: {
  //         'Authorization': `Bearer ${apiKey}`,
  //         'Content-Type': 'application/json'
  //       },
  //       body: JSON.stringify({ Report: result })
  //     });
  
  //     if (!response.ok) {
  //       throw new Error(`HTTP error! status: ${response.status}`);
  //     }
  
  //     const data = await response.json();
  //     console.log('Flow triggered:', data);
  
  //     if (data.data && data.data.fileurl) {
  //       const link = document.createElement('a');
  //       link.href = data.data.fileurl;
  //       link.download = ''; // Optional
  //       document.body.appendChild(link);
  //       link.click();
  //       document.body.removeChild(link);
  //     } else {
  //       console.warn('No file URL found in response.');
  //     }
  
  //   } catch (error) {
  //     console.error('Error triggering flow:', error);
  //   }
  // }
  async function triggerFlow(report) {
    const apiKey = 'wh_m98i5sr8Dh2c0W7fj3t8z8E13mKs8l5xfPtiNAhm';
    const endpoint = 'https://api.worqhat.com/flows/trigger/76135102-bc2e-4bd3-a1a8-7e41477dd5aa';
    console.log("report in the function is ",report);
    try {
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${apiKey}`,
          'Content-Type': 'application/json'
        },
        body:JSON.stringify({ Report: report })  // <-- Pass report directly
      });
  
      if (!response.ok) {
        throw new Error(`HTTP error! Status: ${response.status}`);
      }
  
      const data = await response.json();
      console.log('Flow triggered successfully:', data);
      return data;
  
    } catch (error) {
      console.error('Error triggering flow:', error);
      throw error;
    }
  }
  const handleDownload = () => {
    if (!result) return;
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `websafe_report_${new Date().toISOString().split('T')[0]}.json`;
    //link.click();
  };

  useEffect(() => {
    document.querySelector('input').focus();
  }, []);

  return (
    <div className="app-container">
      <h2 className="title">🔐 WebSafe Sentinel</h2>
      <div className="input-group">
        <input
          type="text"
          placeholder="Enter website URL (e.g., https://example.com)"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          onKeyPress={(e) => e.key === 'Enter' && handleScan()}
          disabled={loading}
          aria-label="Enter website URL"
        />
        <button onClick={handleScan} disabled={loading} aria-label="Scan website">
          {loading ? "Scanning..." : "Scan"}
        </button>
      </div>

      {error && <div className="error-message" role="alert">{error}</div>}

      {result && (
        <div className="results-panel">
          <h3 onClick={() => document.querySelector('.results-details').classList.toggle('collapsed')}>
            Scan Results <span>{result.summary.status === "Completed" ? "✅" : "❌"}</span>
          </h3>
          <div className="results-details">
            <p><strong>Timestamp:</strong> {result.timestamp}</p>
            <p><strong>Issues Found:</strong> {result.summary.issues_found} / {result.summary.total_scans}</p>
            <ul>
              {Object.entries(result.scans).map(([scan, data]) => (
                <li key={scan}>
                  <strong>{scan.replace('_', ' ').charAt(0).toUpperCase() + scan.replace('_', ' ').slice(1)}:</strong>
                  <ul>
                    <li><strong>Status:</strong> {data.status}</li>
                    <li><strong>Result:</strong> {JSON.stringify(data.result)}</li>
                    <li><strong>Details:</strong>
                      <ul>
                        {data.details.map((detail, i) => (
                          <li key={i}>{detail}</li>
                        ))}
                      </ul>
                    </li>
                    <li><strong>Recommendation:</strong> {data.recommendation}</li>
                  </ul>
                </li>
              ))}
            </ul>
            <button onClick={() => {
  if (reportUrl) {
    const link = document.createElement('a');
    link.href = reportUrl;
    link.download = ''; // Optional: name the file
    link.click();
  } else {
    alert("Report not ready yet. Please wait...");
  }
}} disabled={!result}>
  Download Full Report
</button>
          </div>
        </div>
      )}

      {loading && <div className="loading">Scanning... Please wait.</div>}
    </div>
  );
}

export default App;

// {
//   "manifest_version": 3,
//   "name": "WebSafe Sentinel",
//   "version": "1.0",
//   "description": "Web security scanning tool",
//   "permissions": [
//     "activeTab",
//     "storage"
//   ],
//   "action": {
//     "default_popup": "public/index.html",
//     "default_icon": {

//     }
//   },

//   "web_accessible_resources": [
//     {
//       "resources": ["index.css", "App.css"],
//       "matches": ["<all_urls>"]
//     }
//   ]
// }