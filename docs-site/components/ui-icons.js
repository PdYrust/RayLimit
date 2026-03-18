function IconBase({ children, className, viewBox = "0 0 24 24" }) {
  return (
    <svg
      viewBox={viewBox}
      aria-hidden="true"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
    >
      {children}
    </svg>
  );
}

export function CopyIcon({ className }) {
  return (
    <IconBase className={className}>
      <rect x="9" y="9" width="11" height="11" rx="2" />
      <path d="M15 9V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h3" />
    </IconBase>
  );
}

export function CheckIcon({ className }) {
  return (
    <IconBase className={className}>
      <path d="m5 12 4.2 4.2L19 6.8" />
    </IconBase>
  );
}

export function MenuIcon({ className }) {
  return (
    <IconBase className={className}>
      <path d="M4 7h16" />
      <path d="M4 12h16" />
      <path d="M4 17h16" />
    </IconBase>
  );
}

export function CloseIcon({ className }) {
  return (
    <IconBase className={className}>
      <path d="M6 6 18 18" />
      <path d="M18 6 6 18" />
    </IconBase>
  );
}
