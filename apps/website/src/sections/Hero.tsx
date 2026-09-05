import { useRef, type PointerEvent } from "react";
import heroApparatus from "../assets/hero-apparatus.png";
import { ButtonLink } from "../components/ButtonLink";
import { ShieldIcon } from "../components/Icons";
import { RELEASE_URL } from "../content";

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
          Verifiable work. A new monetary frontier.
        </h1>
        <p>
          Open GPU infrastructure with serious cryptography and deliberate
          monetary design. ForgeMatrix pairs consumer-GPU proof of work with
          independent verification, declining issuance and permanently burned
          fees. RC5 puts that vision into software you can run.
        </p>

        <div className="hero__actions">
          <ButtonLink
            href={RELEASE_URL}
            target="_blank"
            rel="noopener noreferrer"
          >
            Download RC5
          </ButtonLink>
          <ButtonLink href="#thesis" variant="secondary">
            Read the thesis
          </ButtonLink>
        </div>

        <div className="trust-note">
          <ShieldIcon />
          <span>RCNet-1 release candidate · No premine · No token sale</span>
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
        <span>Built to verify. Designed for the long term.</span>
        <i aria-hidden="true">+</i>
      </a>
    </section>
  );
}
