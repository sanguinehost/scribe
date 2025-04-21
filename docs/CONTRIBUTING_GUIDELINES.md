# Scribe - Contributing Guidelines & Community Rewards

We welcome contributions to Scribe! This document outlines how you can contribute and how we plan to recognize and reward contributions as the project grows, aligning with the Sanguine philosophy of openness, transparency, and shared success.

## 1. Getting Started with Contributions

*   **Code Contributions:** Find issues tagged "good first issue" or "help wanted" in our GitHub repository. Follow standard pull request procedures (fork, branch, commit, PR). Ensure your code adheres to project standards and includes tests.
*   **Bug Reports & Feature Requests:** Use GitHub Issues to report bugs or suggest new features. Provide clear descriptions and steps to reproduce (for bugs).
*   **Documentation:** Improvements to documentation (`docs/` directory, code comments) are highly valued. Submit PRs for documentation changes.
*   **Community Support:** Help others in our community channels (e.g., Discord, GitHub Discussions) by answering questions or providing guidance.

## 2. Initial Recognition & Funding Tools (Phase 1)

To facilitate immediate community support and transparency, we utilize the following tools:

| Tool              | Purpose                                                                 | Link / Status        |
| :---------------- | :---------------------------------------------------------------------- | :------------------- |
| **GitHub Sponsors** | Allows one-off or recurring donations directly via GitHub.              | *(To be set up)*     |
| **Open Collective** | Provides a transparent public ledger for all donations and expenses.    | *(To be set up)*     |

**Initial Flow:**

1.  An **Open Collective** page for Scribe will be established.
2.  **GitHub Sponsors** will be configured to funnel donations into the Open Collective budget.
3.  The Open Collective budget will be **publicly visible**.
4.  Selected GitHub issues may be tagged with **bounties**, potentially using pooled community funds or personal funds to advertise specific work on platforms like **Upwork** if no community members are immediately available.
    *(Note: Initially, bounties may be small ($50-$100 USD range) reflecting the project's early stage and funding availability.)*

## 3. Future Profit-Sharing Framework: "Contributor Dividend" (Phase 2)

Should Sanguine Host (the potential future hosted service for Scribe and other tools) become profitable, we are committed to sharing a portion of that success with the open-source contributors who make it possible.

**Formula:**

```
Annual Net Profit = Revenue - COGS - Salaries - Infrastructure Costs - Taxes
Contributor Pool = Annual Net Profit * 10% (Initial Target Percentage)
```

**Distribution Key (Example - Subject to Community Review):**

| Weight | Metric                                                       | Rationale                                                    |
| :----- | :----------------------------------------------------------- | :----------------------------------------------------------- |
| 60%    | Merged Lines of Code (LOC) × Quality Score (Reviewed PRs, LOC capped) | Rewards tangible code contributions that meet quality standards. |
| 25%    | Issue Triaging & Code Review Hours (Tracked via GitHub/Tags) | Recognizes essential non-coding technical work.              |
| 10%    | Documentation & Tutorials (Merged to `docs/` or official channels) | Values content that helps grow and sustain the ecosystem.    |
| 5%     | Community Leadership & Ambassadorship (e.g., Moderation, Meetups, Blogs) | Rewards efforts that build and maintain the community fabric. |

**Process:**

*   A script will be run periodically (e.g., quarterly) to calculate scores based on GitHub API data and other tracked metrics.
*   The calculation methodology and results (normalized scores) will be published transparently (e.g., via Open Collective updates).
*   Payouts will be processed through Open Collective or other suitable platforms (e.g., Stripe, PayPal), handling necessary tax documentation where possible.

**Governance:**

*   A `CONTRIBUTOR_AGREEMENT.md` will detail the dividend policy, metrics, and dispute/appeal process.
*   Regular community reviews (e.g., annually) will allow for discussion and potential adjustments to the formula via a transparent process (e.g., weighted voting based on past contributions).

## 4. Feature Bounty Program (Phase 2/3 - Requires Healthy Funding)

As funding allows (potentially seeded from the Contributor Pool before dividends), we plan to implement a more structured feature bounty program:

1.  **Roadmap RFC:** Core team proposes major roadmap items quarterly, tagged with complexity/estimated value.
2.  **Bounty Budget Allocation:** A specific budget is allocated for bounties.
3.  **Issue Tagging:** Issues are tagged with specific bounty amounts (e.g., `bounty:$500`).
4.  **Proposal Requirement:** For significant bounties, a brief design proposal PR may be required for review before implementation begins.
5.  **Payout:** Upon merge of the completed feature (passing tests and review), the bounty is paid out via Open Collective.
    *(Note: While larger bounties are envisioned long-term, initial bounty amounts will depend heavily on available funding and may start small.)*

## 5. Legal & Tax Considerations

*   **Intellectual Property (IP):** Contributions will be subject to the project's open-source license (e.g., MIT, Apache 2.0 - *License TBD*). A Contributor License Agreement (CLA) may be implemented (e.g., using CLA-Assistant) to clarify IP ownership and rights granted to the project.
*   **Contributor Status:** Payments made through systems like Open Collective are typically treated as income for independent contractors. Open Collective assists with tax forms (like 1099s for US contributors exceeding thresholds). Contributors are responsible for their own tax obligations.
*   **Equity:** This program focuses on cash rewards/dividends based on contributions and potential profits. No equity or promise of future equity is implied by this contribution framework at this stage. Formal equity programs (like advisor options) would be separate considerations if Sanguine incorporates formally later.

## 6. Cultural Recognition (Ongoing)

Beyond financial rewards, we value recognizing contributions culturally:

*   **Hall of Fame:** A `HALL_OF_FAME.md` file in the repository acknowledging top contributors annually.
*   **Merchandise:** Occasional limited-run merchandise (stickers, t-shirts) for significant contributions (e.g., first merged PR, major feature completion).
*   **Influence:** Potentially implementing systems where donations or contributions grant credits for voting on roadmap priorities or feature requests.

## Alignment with Sanguine Philosophy

This framework aims to embody the Sanguine Doctrine:

*   **Knowledge = Liberation:** Transparent finances (Open Collective) and clear reward formulas.
*   **Self-Determination:** Contributors choose how they engage, whether through general contributions or specific bounties.
*   **Unity Through Diversity:** Valuing code, documentation, reviews, and community building contributions in the reward structure.
*   **Conscious Indulgence:** Financial rewards supplement intrinsic motivation, acknowledging effort without making it the sole driver.

We believe this approach fosters a healthy, sustainable, and rewarding open-source community aligned with our long-term vision. We welcome feedback on these guidelines!