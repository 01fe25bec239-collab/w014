import React from "react";

export interface FilterBarProps {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  label?: string;
  count?: number;
  totalCount?: number;
  className?: string;
  id?: string;
}

/**
 * Accessible Filter & Search bar component.
 */
export function FilterBar({
  value,
  onChange,
  placeholder = "Filter by name or slug...",
  label = "Filter records",
  count,
  totalCount,
  className = "",
  id = "filter-input",
}: FilterBarProps) {
  return (
    <div className={`filter-bar ${className}`.trim()} role="search">
      <div className="filter-bar-input-wrap">
        <label htmlFor={id} className="sr-only">
          {label}
        </label>
        <input
          id={id}
          type="search"
          className="form-input filter-input"
          placeholder={placeholder}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          data-testid="filter-input"
        />
        {value && (
          <button
            type="button"
            className="filter-clear-btn"
            onClick={() => onChange("")}
            aria-label="Clear filter"
            data-testid="filter-clear-btn"
          >
            ✕
          </button>
        )}
      </div>

      {count !== undefined && (
        <div className="filter-count-badge" aria-live="polite" data-testid="filter-count">
          <span>
            Showing {count}
            {totalCount !== undefined && totalCount !== count ? ` of ${totalCount}` : ""}
          </span>
        </div>
      )}
    </div>
  );
}
