"use client"

import { DashboardLayout } from "@/components/dashboard-layout"
import { useEffect, useState } from "react"

// Alert type
interface Alert {
  message: string
  timestamp?: string
}

// DashboardContent component: shows live security alerts
function DashboardContent() {
  const [alerts, setAlerts] = useState<Alert[]>([])

  useEffect(() => {
    const eventSource = new EventSource("https://codedefenders-cih-2-0.onrender.com/events")

    eventSource.onmessage = (event) => {
      const alert: Alert = JSON.parse(event.data)
      console.log("🟢 Received alert:", alert);
      setAlerts((prev) => [alert, ...prev])
    }

    eventSource.onerror = (err) => {
      console.error("❌ SSE error", err)
      eventSource.close()
    }

    return () => {
      eventSource.close()
    }
  }, [])

  return (
    <div className="p-4">
      <h1 className="text-xl font-bold mb-2">Live Security Alerts</h1>
      <ul className="space-y-2">
        {alerts.slice(0, 10).map((alert, i) => (
          <li key={i} className="p-2 bg-red-100 border border-red-400 rounded">
            <div className="font-semibold">⚠️ {alert.message}</div>
            <div className="text-xs text-gray-600">{alert.timestamp}</div>
          </li>
        ))}
      </ul>
    </div>
  )
}

export default function HomePage() {
  const [alerts, setAlerts] = useState<Alert[]>([])

  useEffect(() => {
    const apiUrl = process.env.NEXT_PUBLIC_API_URL || "https://codedefenders-cih-2-0.onrender.com"

    const evtSource = new EventSource(`${apiUrl}/events`)

    evtSource.onmessage = (event) => {
      const alert: Alert = JSON.parse(event.data)
      setAlerts((prev) => [...prev, alert])

      if (typeof window !== "undefined" && "Notification" in window) {
        if (Notification.permission === "granted") {
          new Notification("🚨 CyberSentinel Alert", {
            body: alert.message
          })
        } else if (Notification.permission !== "denied") {
          Notification.requestPermission().then((permission) => {
            if (permission === "granted") {
              new Notification("🚨 CyberSentinel Alert", {
                body: alert.message
              })
            }
          })
        }
      }
    }

    evtSource.onerror = (err) => {
      console.error("SSE error:", err)
      evtSource.close()
    }

    return () => {
      evtSource.close()
    }
  }, [])

  return (
    <DashboardLayout>
      <DashboardContent />
      <div className="p-4">
          <h2 className="text-xl font-bold mb-2">🔔 Live Alerts</h2>
          <ul className="space-y-2">
            {alerts.map((alert, i) => (
              <li key={i} className="bg-red-100 p-2 rounded shadow">
                {alert.message}
              </li>
            ))}
          </ul>
        </div>
      </DashboardLayout>
  )
}
