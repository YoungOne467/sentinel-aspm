import React from 'react';
import { render, screen } from '@testing-library/react';
import App from '../App';
import { vi } from 'vitest';

// Mock the Layout component
vi.mock('../components/Layout', () => {
  return {
    default: function DummyLayout() {
      return <div data-testid="layout-mock">Mocked Layout</div>;
    }
  };
});

describe('App Component', () => {
  it('renders the App component with Layout', () => {
    render(<App />);
    expect(screen.getByTestId('layout-mock')).toBeInTheDocument();
  });
});
