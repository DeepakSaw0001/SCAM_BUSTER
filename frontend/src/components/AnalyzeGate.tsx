import React from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { AuthGate } from './AuthGate';

interface AnalyzeGateProps {
  children: React.ReactNode;
}

/**
 * AnalyzeGate:
 * - Appears only once for non-logged-in users when they click/enter the analyze section.
 * - Does NOT appear on the main page of the website.
 * - Once the user is logged in (or dismisses the gate), it never appears again for that user.
 */
export const AnalyzeGate: React.FC<AnalyzeGateProps> = ({ children }) => {
  const { isAuthenticated, hasSeenAuthGate, markAuthGateSeen } = useAuth();
  const navigate = useNavigate();

  // If the user is logged in, or has already encountered & handled the gate once:
  if (isAuthenticated || hasSeenAuthGate) {
    return <>{children}</>;
  }

  // First-time non logged-in visitor attempting to access the analyze section:
  return (
    <AuthGate
      onSuccess={() => {
        markAuthGateSeen();
      }}
      onDismiss={() => {
        markAuthGateSeen();
      }}
      onBackHome={() => {
        navigate('/');
      }}
    />
  );
};

export default AnalyzeGate;
