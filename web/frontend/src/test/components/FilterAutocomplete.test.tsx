import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { FilterAutocomplete } from '../../components/FilterAutocomplete';

describe('FilterAutocomplete', () => {
  it('renders input with placeholder', () => {
    render(
      <FilterAutocomplete value="" onChange={() => {}} />
    );
    const input = screen.getByPlaceholderText(/ip\.src/i);
    expect(input).toBeInTheDocument();
  });

  it('shows suggestions when input is focused with empty value', () => {
    render(
      <FilterAutocomplete value="" onChange={() => {}} />
    );
    const input = screen.getByRole('textbox');
    fireEvent.focus(input);
    // Should show field suggestions (ip.src, ip.dst, etc.)
    expect(screen.getByText('ip.src')).toBeInTheDocument();
    expect(screen.getByText('ip.dst')).toBeInTheDocument();
  });

  it('filters suggestions when typing a partial field name', () => {
    const onChange = vi.fn();
    render(
      <FilterAutocomplete value="tcp" onChange={onChange} />
    );
    const input = screen.getByRole('textbox');
    fireEvent.focus(input);
    // Should show tcp-related fields
    expect(screen.getByText('tcp.port')).toBeInTheDocument();
    expect(screen.getByText('tcp.srcport')).toBeInTheDocument();
  });

  it('calls onChange when a suggestion is clicked', () => {
    const onChange = vi.fn();
    render(
      <FilterAutocomplete value="" onChange={onChange} />
    );
    const input = screen.getByRole('textbox');
    fireEvent.focus(input);

    // Suggestions are rendered as buttons with onClick handler
    const suggestion = screen.getByText('ip.src');
    const btn = suggestion.closest('button');
    if (btn) fireEvent.click(btn);
    expect(onChange).toHaveBeenCalled();
  });

  it('calls onApply when Enter is pressed', () => {
    const onApply = vi.fn();
    render(
      <FilterAutocomplete value="ip.src == 10.0.0.1" onChange={() => {}} onApply={onApply} />
    );
    const input = screen.getByRole('textbox');
    fireEvent.keyDown(input, { key: 'Enter' });
    expect(onApply).toHaveBeenCalledWith('ip.src == 10.0.0.1');
  });

  it('renders clear button when value is non-empty', () => {
    render(
      <FilterAutocomplete value="ip.src" onChange={() => {}} />
    );
    // Look for the X/clear button
    const buttons = screen.getAllByRole('button');
    expect(buttons.length).toBeGreaterThan(0);
  });
});
