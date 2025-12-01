\subsubsection{Cybench}

Cybench is a comprehensive benchmark for evaluating the cybersecurity capabilities of language models through practical Capture The Flag (CTF) challenges \parencite{zhang2025cybenchframeworkevaluatingcybersecurity}. What makes Cybench unique is its use of 40 professional-level CTF tasks sourced from four distinct competitions: HackTheBox 2024, SekaiCTF 2022-23, Glacier 2023, and HKCert 2023 \parencite{zhang2025cybenchframeworkevaluatingcybersecurity}.

Unlike other cybersecurity benchmarks that rely on theoretical knowledge questions or simplified vulnerability detection, Cybench evaluates language model agents in realistic environments where they must autonomously identify vulnerabilities, develop exploits, and execute them to capture flags \parencite{zhang2025cybenchframeworkevaluatingcybersecurity}. Each task includes a complete environment setup with task descriptions, starter files, and evaluators that verify successful flag submissions.

The key innovation of Cybench is its introduction of subtasks that break complex challenges into intermediate steps, enabling more granular assessment of agent capabilities and partial credit evaluation \parencite{zhang2025cybenchframeworkevaluatingcybersecurity}. This approach allows researchers to identify exactly where language models fail in multi-step exploitation processes.

Compared to other cybersecurity benchmarks, Cybench offers several distinct advantages:

\begin{enumerate}
\item \textbf{Real-world complexity}: While CyberMetric focuses on multiple-choice questions testing cybersecurity knowledge \parencite{tihanyi2024cybermetricbenchmarkdatasetbased} and CyberSecEval 2 uses simplified vulnerability scenarios \parencite{bhatt2024cyberseceval2widerangingcybersecurity}, Cybench employs actual CTF challenges from professional competitions with objective difficulty ratings ranging from 2 minutes to 24 hours and 54 minutes in first solve time \parencite{zhang2025cybenchframeworkevaluatingcybersecurity}.

    \item \textbf{Interactive environments}: Unlike the static evaluation approaches of CyberMetric and CyberSecEval 2, Cybench provides interactive environments where agents can execute commands, observe outputs, and interact with remote servers, closely mimicking real penetration testing scenarios \parencite{zhang2025cybenchframeworkevaluatingcybersecurity}.

    \item \textbf{Multi-step process evaluation}: Cybench evaluates the complete exploitation process rather than just the final answer, providing insights into how well language models can handle the sequential reasoning required for cybersecurity tasks \parencite{zhang2025cybenchframeworkevaluatingcybersecurity}.

\end{enumerate}

The Cybench evaluation revealed that even the best-performing models (Claude 3.5 Sonnet at 17.5\% and GPT-4o at 12.5\%) could only solve tasks with first solve times of 11 minutes or less, with none successfully solving challenges that took human teams longer than 11 minutes \parencite{zhang2025cybenchframeworkevaluatingcybersecurity}. This demonstrates the significant gap between current language model capabilities and human expertise in complex cybersecurity challenges.

Cybench has been adopted by major AI safety organizations including the US and UK AISI, Anthropic, Amazon, and OWASP, establishing it as the current state-of-the-art benchmark for evaluating language model cybersecurity capabilities \parencite{zhang2025cybenchframeworkevaluatingcybersecurity}.
