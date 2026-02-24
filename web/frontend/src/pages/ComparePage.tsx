import { ComparisonView } from '../components';
import { useNavigate } from 'react-router-dom';

export function ComparePage() {
  const navigate = useNavigate();

  return (
    <div className="max-w-7xl mx-auto px-4 py-8">
      <ComparisonView onClose={() => navigate('/')} />
    </div>
  );
}
