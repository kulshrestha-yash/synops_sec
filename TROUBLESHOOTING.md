# NeuroShield - Troubleshooting Guide

## ✅ Server is Running Successfully!

Your server started correctly in **ML MODE** with trained models loaded.

## 🌐 How to Access the Dashboard

### Option 1: Use localhost (Recommended)
Open your browser and go to:
```
http://localhost:8000/dashboard/
```

### Option 2: Use 127.0.0.1
```
http://127.0.0.1:8000/dashboard/
```

### Option 3: Test API first
```
http://localhost:8000/health
```

## 🔧 If Page Won't Load

### 1. Clear Browser Cache
- Press `Ctrl + Shift + Delete`
- Clear cached images and files
- Try again

### 2. Try Different Browser
- Chrome: http://localhost:8000/dashboard/
- Edge: http://localhost:8000/dashboard/
- Firefox: http://localhost:8000/dashboard/

### 3. Check Firewall
Windows Firewall might be blocking the connection. Allow Python through firewall:
- Search "Windows Defender Firewall"
- Click "Allow an app through firewall"
- Find Python and check both Private and Public

### 4. Use PowerShell to Test
```powershell
# Test if server responds
Invoke-WebRequest -Uri http://localhost:8000/health -UseBasicParsing

# Should return JSON with status information
```

### 5. Check Server Logs
The server should show:
```
INFO:     Uvicorn running on http://0.0.0.0:8000
INFO:     Application startup complete.
```

When you access the page, you should see:
```
GET /dashboard/ - 200 OK
```

## 🚀 Quick Test

1. Open PowerShell in a NEW window
2. Run:
```powershell
Invoke-RestMethod http://localhost:8000/health
```

3. You should see JSON output like:
```json
{
  "status": "healthy",
  "mode": "ml",
  "ml_enabled": true
}
```

## 📱 What You Should See

Once loaded, the dashboard shows:
- 🛡️ **Header**: NeuroShield branding with status indicator
- 📊 **Metrics**: Total analyzed, threats detected, threshold, adaptations
- 🔍 **Analyzer**: Text area to input system call sequences
- 📈 **Chart**: Real-time threat timeline
- 📋 **Table**: Recent threats with severity levels

## 🎯 Test the Analyzer

1. Click a sample button (Ransomware/Reverse Shell/Normal)
2. Click "🔍 Analyze Threat"
3. See results with color-coded severity

## ⚡ Common Issues

### "Connection Refused"
- Server is still starting - wait 5 seconds
- Port 8000 is blocked - check firewall
- Another app using port 8000 - stop it first

### "Page Not Found (404)"
- Add trailing slash: `/dashboard/` not `/dashboard`
- Files missing - check `dashboard/` folder exists

### "Blank Page"
- Open browser console (F12)
- Look for JavaScript errors
- Check if styles.css and app.js loaded

### "API Offline" in Dashboard
- Server stopped - restart `python api/server.py`
- WebSocket issue - refresh page
- Use polling fallback (automatic after 5 seconds)

## 🔍 Debugging Steps

1. **Verify server is running**:
   ```powershell
   Get-NetTCPConnection -LocalPort 8000
   ```

2. **Test API endpoint**:
   ```powershell
   curl http://localhost:8000 -UseBasicParsing
   ```

3. **Check dashboard files exist**:
   ```powershell
   ls dashboard/
   # Should show: index.html, styles.css, app.js
   ```

4. **View server logs**:
   Watch the terminal where `python api/server.py` is running for errors

## 💡 Browser Console

Press `F12` in your browser and check:
- **Console tab**: JavaScript errors
- **Network tab**: Failed requests (should see 200 OK for files)
- **Application tab**: Check if files loaded

## ✅ Success Indicators

When working correctly, you'll see:
- Green "API Online" or "Live Stream Active" status
- Metrics updating with numbers
- Chart displaying
- Sample buttons work
- Threats table shows message

## 📞 Still Not Working?

1. Restart server: `Ctrl+C` then `python api/server.py`
2. Try: `http://localhost:8000/` (root endpoint)
3. Check if you can see API info JSON
4. Then try: `http://localhost:8000/dashboard/index.html` (direct file)

## 🎉 Alternative: Direct File Access

If still failing, you can open the dashboard directly:
```powershell
start dashboard/index.html
```

But you'll need to set the API endpoint in browser console:
```javascript
localStorage.setItem("neuroshieldApiBase", "http://localhost:8000");
```
Then refresh the page.

---

**Note**: The server logs show successful ML mode startup. The dashboard should work - it's likely a browser or network issue.
