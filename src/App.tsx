import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Route, Routes, Navigate } from "react-router-dom";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { ThemeProvider } from "@/context/ThemeContext";
import { DashboardLayout } from "@/components/DashboardLayout";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import InputTarget from "./pages/InputTarget";
import Scanning from "./pages/Scanning";
import ScanHistory from "./pages/ScanHistory";
import ScanDetails from "./pages/ScanDetails";
import Vulnerabilities from "./pages/Vulnerabilities";
import Reports from "./pages/Reports";
import SettingsPage from "./pages/SettingsPage";
import MobileScan from "./pages/MobileScan";
import MobileScans from "./pages/MobileScans";
import MobileScanDetails from "./pages/MobileScanDetails";
import NetworkScan from "./pages/NetworkScan";
import GarakScan from "./pages/GarakScan";
import NotFound from "./pages/NotFound";

const queryClient = new QueryClient();

const App = () => (
  <ThemeProvider>
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <Toaster />
        <Sonner />
        <BrowserRouter>
          <Routes>
            <Route path="/" element={<Login />} />
            <Route element={<DashboardLayout />}>
              <Route path="/dashboard" element={<Dashboard />} />
              <Route path="/input-target" element={<InputTarget />} />
              <Route path="/scanning" element={<Scanning />} />
              <Route path="/scan-history" element={<ScanHistory />} />
              <Route path="/scan-details/:id" element={<ScanDetails />} />
              <Route path="/vulnerabilities" element={<Vulnerabilities />} />
              <Route path="/reports" element={<Reports />} />
              <Route path="/settings" element={<SettingsPage />} />
              <Route path="/mobile-scan" element={<MobileScan />} />
              <Route path="/mobile-scans" element={<MobileScans />} />
              <Route path="/mobile-scan-details/:hash" element={<MobileScanDetails />} />
              <Route path="/network-scan" element={<NetworkScan />} />
              <Route path="/garak-scan" element={<GarakScan />} />
            </Route>
            <Route path="*" element={<NotFound />} />
          </Routes>
        </BrowserRouter>
      </TooltipProvider>
    </QueryClientProvider>
  </ThemeProvider>
);

export default App;
