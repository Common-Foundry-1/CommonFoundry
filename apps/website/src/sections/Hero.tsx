import { useRef, type PointerEvent } from "react";
import heroApparatus from "../assets/hero-apparatus.png";
import { ButtonLink } from "../components/ButtonLink";
import { ShieldIcon } from "../components/Icons";
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
      <div className="hero__copy">
        <h1 id="hero-heading">
          Open GPU infrastructure for work, settlement, and inference.
        </h1>
        <p>
          Common Foundry is a research-first proof-of-work protocol aligning GPU
          operators with direct inference markets—without pretending mining is
          customer inference.
        </p>

        <div className="hero__actions">
          <ButtonLink
            href={DISCORD_URL}
            target="_blank"
            rel="noopener noreferrer"
          >
            Join the Devnet
          </ButtonLink>
          <ButtonLink href="#thesis" variant="secondary">
            Read the thesis
          </ButtonLink>
        </div>

        <div className="trust-note">
          <ShieldIcon />
          <span>Devnet-0 is experimental, private, and valueless. No token sale.</span>
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
          <span><i className="legend-square" />Proof of work</span>
          <b />
          <span><i className="legend-line" />Inference work</span>
          <b />
          <span><i className="legend-hex" />Market settlement</span>
        </div>
      </div>

      <a className="section-preview" href="#thesis">
        <span>One hardware base. Two economic roles.</span>
        <i aria-hidden="true">+</i>
      </a>
    </section>
  );
}
