import { Header } from "./components/Header";
import { Economics } from "./sections/Economics";
import { Hero } from "./sections/Hero";
import { Launch } from "./sections/Launch";
import { Progress } from "./sections/Progress";
import { Roadmap } from "./sections/Roadmap";
import { Thesis } from "./sections/Thesis";

export default function App() {
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
