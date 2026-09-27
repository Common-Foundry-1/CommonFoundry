import type { SVGProps } from "react";
import type { ProgressIcon } from "../content";

type IconProps = SVGProps<SVGSVGElement>;

const commonProps = {
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.6,
  strokeLinecap: "round" as const,
  strokeLinejoin: "round" as const,
  "aria-hidden": true,
};

export function ArrowIcon(props: IconProps) {
  return (
    <svg {...commonProps} {...props}>
      <path d="M4 12h15" />
      <path d="m14 6 6 6-6 6" />
    </svg>
  );
}

export function MenuIcon(props: IconProps) {
  return (
    <svg {...commonProps} {...props}>
      <path d="M4 6h16M4 12h16M4 18h16" />
    </svg>
  );
}

export function CloseIcon(props: IconProps) {
  return (
    <svg {...commonProps} {...props}>
      <path d="m5 5 14 14M19 5 5 19" />
    </svg>
  );
}

export function ShieldIcon(props: IconProps) {
  return (
    <svg {...commonProps} {...props}>
      <path d="M12 3 19 6v5c0 4.8-2.8 8.3-7 10-4.2-1.7-7-5.2-7-10V6l7-3Z" />
      <path d="m9 12 2 2 4-5" />
    </svg>
  );
}

export function FlameIcon(props: IconProps) {
  return (
    <svg {...commonProps} {...props}>
      <path d="M13 3c.8 3-1.5 4.2-1.5 6.3 0 1.2.8 2 1.8 2.7.4-1.8 1.4-3 2.7-4.1 1.4 1.8 2.2 3.6 2.2 5.7A6.2 6.2 0 1 1 7.7 9.1C8.4 12 10 12.2 10.8 14c1-1.3 1.1-2.7.7-4.1C10.9 7.7 11.2 5.4 13 3Z" />
    </svg>
  );
}

export function DocumentIcon(props: IconProps) {
  return (
    <svg {...commonProps} {...props}>
      <path d="M6 3h8l4 4v14H6z" />
      <path d="M14 3v5h5M9 13h6M9 17h6" />
    </svg>
  );
}

export function XIcon(props: IconProps) {
  return (
    <svg {...commonProps} {...props}>
      <path d="M5 4 19 20M19 4 5 20" />
    </svg>
  );
}

export function ProgressGlyph({ kind, ...props }: IconProps & { kind: ProgressIcon }) {
  if (kind === "lock") {
    return (
      <svg {...commonProps} {...props}>
        <rect x="6" y="10" width="12" height="10" rx="1" />
        <path d="M8.5 10V7.5a3.5 3.5 0 0 1 7 0V10M12 14v2.5" />
      </svg>
    );
  }

  if (kind === "wallet") {
    return (
      <svg {...commonProps} {...props}>
        <path d="M4 7h14a2 2 0 0 1 2 2v9H5a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h11" />
        <path d="M15 11h6v4h-6a2 2 0 1 1 0-4Z" />
      </svg>
    );
  }

  if (kind === "burn") {
    return <FlameIcon {...props} />;
  }

  if (kind === "network") {
    return (
      <svg {...commonProps} {...props}>
        <path d="m12 3 7 4v10l-7 4-7-4V7zM5 7l7 4 7-4M12 11v10M8 5l8 14M16 5 8 19" />
      </svg>
    );
  }

  if (kind === "channel") {
    return (
      <svg {...commonProps} {...props}>
        <path d="M4 17h5v4H4zM15 3h5v4h-5zM15 17h5v4h-5zM6.5 17v-4h11V7M9 15l3-2-3-2" />
      </svg>
    );
  }

  return (
    <svg {...commonProps} {...props}>
      <path d="m12 3 5 3v6l-5 3-5-3V6zM7 12l-4 2.5V20l5 3 4-2.5V15M17 12l4 2.5V20l-5 3-4-2.5" />
    </svg>
  );
}
