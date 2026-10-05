import { useRef, type PointerEvent } from "react";
import heroApparatus from "../assets/hero-apparatus.png";
import { ButtonLink } from "../components/ButtonLink";
import { ShieldIcon } from "../components/Icons";
import { MainnetLive } from "../components/MainnetLive";
import { DISCORD_URL } from "../content";

export function Hero() {
  const visualRef = useRef<HTMLDivElement>(null);

  const updateParallax = (event: PointerEvent<HTMLDivElement>) => {
    if (!visualRef.current || event.pointerType === "touch") return;
    const bounds = event.currentTarget.getBoundingClientRect();
    const x = (event.clientX - bounds.left) / bounds.width - 0.5;
    const y = (event.clientY - bounds.top) / bounds.height - 0.5;
    visualRef.current.style.setProperty("--hero-x", `${x * 10}px`);
    visualRef.current.style.setProperty("--hero-y", `${y * 8}px`);
  };

  const resetParallax = () => {
    visualRef.current?.style.setProperty("--hero-x", "0px");
    visualRef.current?.style.setProperty("--hero-y", "0px");
  };

  return (
    <section id="top" className="hero section-grid" aria-labelledby="hero-heading">
      <MainnetLive />
      <div className="hero__copy">
        <a className="hero__launch-label" href="#launch">Mainnet live since October 3, 2026 <span aria-hidden="true">↗</span></a>
        <h1 id="hero-heading">
          Inference first.<br />Built to lead.
        </h1>
        <p>
          AI compute should belong to more of us. We’re building Common Foundry
          around GPU operators, verifiable work and a path to customer-paid
          inference. Mainnet launched October 3, 2026. Join the people building
          what comes next.
        </p>

        <div className="hero__actions">
          <ButtonLink href={DISCORD_URL} target="_blank" rel="noopener noreferrer">
            Join Discord
          </ButtonLink>
          <ButtonLink href="#launch" variant="secondary">
            Mainnet status
          </ButtonLink>
        </div>

        <p className="hero__support">Setup help. Mining guidance. Release announcements.</p>
        <div className="trust-note">
          <ShieldIcon />
          <span>No premine · No token sale · GPU proof of work</span>
        </div>

      </div>

      <div
        className="hero__visual"
        onPointerMove={updateParallax}
        onPointerLeave={resetParallax}
      >
        <div ref={visualRef} className="hero__art-wrap">
          <img
            src={heroApparatus}
            alt="Matrix cells flowing through a forged computation ring into a distributed network"
            width="1697"
            height="927"
            fetchPriority="high"
          />
        </div>
        <div className="hero__legend" aria-hidden="true">
          <span><i className="legend-square" />GPU operators</span>
          <b />
          <span><i className="legend-line" />Verifiable work</span>
          <b />
          <span><i className="legend-hex" />Inference vision</span>
        </div>
      </div>

      <a className="section-preview" href="#thesis">
        <span>Your hardware. Your ideas. A place in the Foundry.</span>
        <i aria-hidden="true">+</i>
      </a>
    </section>
  );
}
