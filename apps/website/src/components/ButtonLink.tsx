import type { AnchorHTMLAttributes, ReactNode } from "react";
import { ArrowIcon } from "./Icons";

interface ButtonLinkProps extends AnchorHTMLAttributes<HTMLAnchorElement> {
  children: ReactNode;
  variant?: "primary" | "secondary";
}

export function ButtonLink({
  children,
  className = "",
  variant = "primary",
  ...props
}: ButtonLinkProps) {
  return (
    <a className={`button-link button-link--${variant} ${className}`.trim()} {...props}>
      <span>{children}</span>
      <ArrowIcon />
    </a>
  );
}
