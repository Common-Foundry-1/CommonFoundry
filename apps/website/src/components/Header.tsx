import { useEffect, useRef, useState } from "react";
import { DISCORD_URL, WALLET_URL, navItems, type SectionId } from "../content";
import { ArrowIcon, CloseIcon, MenuIcon } from "./Icons";

function useActiveSection() {
  const [activeSection, setActiveSection] = useState<SectionId>("launch");

  useEffect(() => {
    let frame = 0;

    const update = () => {
      const marker = window.scrollY + window.innerHeight * 0.34;
      let active: SectionId = "launch";

      for (const item of navItems) {
        const element = document.getElementById(item.id);
        if (element && element.getBoundingClientRect().top + window.scrollY <= marker) {
          active = item.id;
        }
      }

      setActiveSection(active);
      frame = 0;
    };

    const onScroll = () => {
      if (frame === 0) {
        frame = window.requestAnimationFrame(update);
      }
    };

    update();
    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("resize", onScroll, { passive: true });

    return () => {
      window.removeEventListener("scroll", onScroll);
      window.removeEventListener("resize", onScroll);
      if (frame !== 0) window.cancelAnimationFrame(frame);
    };
  }, []);

  return activeSection;
}

export function Header() {
  const activeSection = useActiveSection();
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  const menuToggleRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!isMenuOpen) return undefined;

    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    menuRef.current?.querySelector<HTMLAnchorElement>("a")?.focus();

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setIsMenuOpen(false);
        menuToggleRef.current?.focus();
      }
    };

    window.addEventListener("keydown", onKeyDown);
    return () => {
      document.body.style.overflow = previousOverflow;
      window.removeEventListener("keydown", onKeyDown);
    };
  }, [isMenuOpen]);

  const closeMenu = () => setIsMenuOpen(false);

  return (
    <header className="site-header">
      <a className="brand" href="#top" aria-label="Common Foundry home">
        <img src="/assets/common-foundry-mark.png" alt="" width="52" height="52" />
        <span>Common Foundry</span>
      </a>

      <nav className="desktop-nav" aria-label="Primary navigation">
        {navItems.map((item) => (
          <a
            key={item.id}
            href={`#${item.id}`}
            aria-current={activeSection === item.id ? "location" : undefined}
          >
            {item.label}
          </a>
        ))}
        <a href={WALLET_URL} target="_blank" rel="noopener noreferrer">Web wallet</a>
      </nav>

      <a
        className="header-cta"
        href={DISCORD_URL}
        target="_blank"
        rel="noopener noreferrer"
      >
        <span>Join Discord</span>
        <ArrowIcon />
      </a>

      <button
        ref={menuToggleRef}
        className="menu-toggle"
        type="button"
        aria-label={isMenuOpen ? "Close navigation" : "Open navigation"}
        aria-expanded={isMenuOpen}
        aria-controls="mobile-menu"
        onClick={() => setIsMenuOpen((open) => !open)}
      >
        {isMenuOpen ? <CloseIcon /> : <MenuIcon />}
      </button>

      <div
        ref={menuRef}
        id="mobile-menu"
        className={`mobile-menu ${isMenuOpen ? "is-open" : ""}`}
        aria-hidden={!isMenuOpen}
        inert={!isMenuOpen}
      >
        <nav aria-label="Mobile navigation">
          {navItems.map((item) => (
            <a key={item.id} href={`#${item.id}`} onClick={closeMenu}>
              <span>{item.label}</span>
              <ArrowIcon />
            </a>
          ))}
          <a href={WALLET_URL} target="_blank" rel="noopener noreferrer" onClick={closeMenu}>
            <span>Web wallet</span>
            <ArrowIcon />
          </a>
        </nav>
        <a
          className="mobile-menu__cta"
          href={DISCORD_URL}
          target="_blank"
          rel="noopener noreferrer"
          onClick={closeMenu}
        >
          <span>Join Discord</span>
          <ArrowIcon />
        </a>
      </div>
    </header>
  );
}
