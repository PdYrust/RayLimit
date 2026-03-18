import { siteMeta } from "../lib/docs";
import { withBasePath } from "../lib/base-path";

function GitHubIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path
        fill="currentColor"
        d="M10.303 16.652c-2.837-.344-4.835-2.385-4.835-5.028 0-1.074.387-2.235 1.031-3.008-.279-.709-.236-2.214.086-2.837.86-.107 2.02.344 2.708.967.816-.258 1.676-.386 2.728-.386 1.053 0 1.913.128 2.686.365.666-.602 1.848-1.053 2.708-.946.3.581.344 2.085.064 2.815.688.817 1.053 1.913 1.053 3.03 0 2.643-1.998 4.641-4.877 5.006.73.473 1.224 1.504 1.224 2.686v2.235c0 .644.537 1.01 1.182.752 3.889-1.483 6.94-5.372 6.94-10.185 0-6.081-4.942-11.044-11.022-11.044-6.081 0-10.98 4.963-10.98 11.044a10.84 10.84 0 0 0 7.112 10.206c.58.215 1.139-.172 1.139-.752v-1.719a2.768 2.768 0 0 1-1.032.215c-1.418 0-2.256-.773-2.857-2.213-.237-.58-.495-.924-.989-.988-.258-.022-.344-.129-.344-.258 0-.258.43-.451.86-.451.623 0 1.16.386 1.719 1.181.43.623.881.903 1.418.903.537 0 .881-.194 1.375-.688.365-.365.645-.687.903-.902Z"
      />
    </svg>
  );
}

function TelegramIcon() {
  return (
    <svg viewBox="0 0 1000 1000" aria-hidden="true">
      <defs>
        <linearGradient id="telegram-gradient-footer" x1="50%" y1="0%" x2="50%" y2="99.2583404%">
          <stop stopColor="#2AABEE" offset="0%" />
          <stop stopColor="#229ED9" offset="100%" />
        </linearGradient>
      </defs>
      <circle fill="url(#telegram-gradient-footer)" cx="500" cy="500" r="500" />
      <path
        fill="#FFFFFF"
        d="M226.328419 494.722069C372.088573 431.216685 469.284839 389.350049 517.917216 369.122161C656.772535 311.36743 685.625481 301.334815 704.431427 301.003532C708.567621 300.93067 717.815839 301.955743 723.806446 306.816707C728.864797 310.92121 730.256552 316.46581 730.922551 320.357329C731.588551 324.248848 732.417879 333.113828 731.758626 340.040666C724.234007 419.102486 691.675104 610.964674 675.110982 699.515267C668.10208 736.984342 654.301336 749.547532 640.940618 750.777006C611.904684 753.448938 589.856115 731.588035 561.733393 713.153237C517.726886 684.306416 492.866009 666.349181 450.150074 638.200013C400.78442 605.66878 432.786119 587.789048 460.919462 558.568563C468.282091 550.921423 596.21508 434.556479 598.691227 424.000355C599.00091 422.680135 599.288312 417.758981 596.36474 415.160431C593.441168 412.561881 589.126229 413.450484 586.012448 414.157198C581.598758 415.158943 511.297793 461.625274 375.109553 553.556189C355.154858 567.258623 337.080515 573.934908 320.886524 573.585046C303.033948 573.199351 268.692754 563.490928 243.163606 555.192408C211.851067 545.013936 186.964484 539.632504 189.131547 522.346309C190.260287 513.342589 202.659244 504.134509 226.328419 494.722069Z"
      />
    </svg>
  );
}

export function SiteFooter() {
  return (
    <footer className="site-footer">
      <div className="site-footer-shell">
        <div className="site-footer-inner">
          <div className="footer-intro">
            <div className="footer-brand-row">
              <img
                className="footer-icon"
                src={withBasePath("/raylimit-icon.svg")}
                alt="RayLimit icon"
                width="30"
                height="30"
              />
              <span className="footer-brand">RayLimit</span>
              <span className="footer-separator" aria-hidden="true" />
              <span className="footer-version">{siteMeta.version}</span>
            </div>
            <p className="footer-summary">{siteMeta.tagline}</p>
          </div>
          <nav className="footer-links" aria-label="External links">
            <a
              className="footer-link github-link"
              href={siteMeta.repository}
              target="_blank"
              rel="noreferrer"
              aria-label="GitHub repository"
            >
              <GitHubIcon />
              <span className="footer-link-label">GitHub</span>
            </a>
            <a
              className="footer-link telegram-link"
              href={siteMeta.telegram}
              target="_blank"
              rel="noreferrer"
              aria-label="Telegram channel"
            >
              <TelegramIcon />
              <span className="footer-link-label">Telegram</span>
            </a>
          </nav>
        </div>
      </div>
    </footer>
  );
}
