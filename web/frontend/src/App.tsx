// Main App component with routing and authentication gate

import { Routes, Route } from 'react-router-dom';
import { Layout } from './components';
import { HomePage, AnalysisPage, ResultsPage, HistoryPage, ComparePage } from './pages';
import { LoginPage } from './pages/LoginPage';
import { useAuth } from './auth/AuthContext';

function App() {
  const { isAuthenticated } = useAuth();

  // Gate: show login page when not authenticated
  if (!isAuthenticated) {
    return <LoginPage />;
  }

  return (
    <Layout>
      <Routes>
        <Route path="/" element={<HomePage />} />
        <Route path="/analysis/:id" element={<AnalysisPage />} />
        <Route path="/results/:id" element={<ResultsPage />} />
        <Route path="/history" element={<HistoryPage />} />
        <Route path="/compare" element={<ComparePage />} />
      </Routes>
    </Layout>
  );
}

export default App;
