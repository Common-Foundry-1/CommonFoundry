import { useEffect } from "react";
import { Header } from "./components/Header";
import { Economics } from "./sections/Economics";
import { Hero } from "./sections/Hero";
import { Launch } from "./sections/Launch";
import { Progress } from "./sections/Progress";
import { Roadmap } from "./sections/Roadmap";
import { Thesis } from "./sections/Thesis";

export default function App() {
  useEffect(() => {
    if (window.location.hash === "#mining-guide" || window.location.hash === "#pool-setup") {
      document.getElementById(window.location.hash.slice(1))?.scrollIntoView({ block: "start" });
    }
  }, []);

  return (
    <>
      <a className="skip-link" href="#main-content">Skip to content</a>
      <Header />
      <main id="main-content">
        <Hero />
        <Launch />
        <Thesis />
        <Progress />
        <Economics />
        <Roadmap />
      </main>
    </>
  );
}
