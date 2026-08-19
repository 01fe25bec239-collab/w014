import React from "react";

export interface CursorPagerProps {
  hasMore: boolean;
  hasPrevious?: boolean;
  onNext: () => void;
  onPrevious?: () => void;
  isLoading?: boolean;
  label?: string;
  className?: string;
}

/**
 * Accessible cursor-based pagination control.
 */
export function CursorPager({
  hasMore,
  hasPrevious = false,
  onNext,
  onPrevious,
  isLoading = false,
  label = "Pagination Navigation",
  className = "",
}: CursorPagerProps) {
  return (
    <nav
      aria-label={label}
      className={`cursor-pager ${className}`.trim()}
      data-testid="cursor-pager"
    >
      <div className="cursor-pager-controls">
        {onPrevious && (
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={onPrevious}
            disabled={!hasPrevious || isLoading}
            aria-disabled={!hasPrevious || isLoading}
            data-testid="pager-prev-btn"
          >
            ← Previous
          </button>
        )}
        <button
          type="button"
          className="btn btn-secondary btn-sm"
          onClick={onNext}
          disabled={!hasMore || isLoading}
          aria-disabled={!hasMore || isLoading}
          data-testid="pager-next-btn"
        >
          Next →
        </button>
      </div>
    </nav>
  );
}
