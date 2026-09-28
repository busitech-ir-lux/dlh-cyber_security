\## 1. Assessment Methodology



This assessment uses the \*\*Admiralty Code\*\*, adapted for cyber threat intelligence.



It separates two questions:



\### Source Reliability — A to F



This rates the \*\*source itself\*\*, based on its history, access, expertise, and ability to obtain reliable information.



| Rating | Meaning |

|---|---|

| \*\*A\*\* | Completely reliable |

| \*\*B\*\* | Usually reliable |

| \*\*C\*\* | Fairly reliable |

| \*\*D\*\* | Not usually reliable |

| \*\*E\*\* | Unreliable |

| \*\*F\*\* | Reliability cannot be judged |



\### Information Credibility — 1 to 6



This separately rates the \*\*specific information being reported\*\*.



| Rating | Meaning |

|---|---|

| \*\*1\*\* | Confirmed by independent sources |

| \*\*2\*\* | Probably true |

| \*\*3\*\* | Possibly true |

| \*\*4\*\* | Doubtful |

| \*\*5\*\* | Improbable |

| \*\*6\*\* | Truth cannot be judged |



For example, `B2` means the source is usually reliable and the reported information is probably true.



\### Analytical Confidence



This assessment also uses:



\- \*\*HIGH\*\* — strong evidence and/or independent corroboration

\- \*\*MEDIUM\*\* — reasonable evidence, but important uncertainty remains

\- \*\*LOW\*\* — limited, weak, indirect, or uncorroborated evidence



Source reliability and information credibility are assessed separately. A generally reliable source can still publish a weakly supported individual claim.



\---



\# 2. Individual Source Assessments



\## 2.1 HC3 Advisory



\*\*Source:\*\* `HC3\_Advisory\_HEALTHBANE\_TLP\_CLEAR.txt`



\*\*Source type:\*\* Government healthcare-sector advisory



\*\*Source reliability:\*\* \*\*A — Completely reliable\*\*



\*\*Information credibility:\*\* \*\*1 — Confirmed by independent sources\*\*



\*\*Overall assessment:\*\* \*\*A1\*\*



\*\*Analytical confidence:\*\* \*\*HIGH\*\* for observed campaign activity; \*\*LOW\*\* for attribution to a named actor.



\### Timeliness



The advisory was published during the active HEALTHBANE campaign and includes activity observed through 2026-04-26. It is therefore timely for defensive use.



\### Relevance to MedDefense



\*\*Very high.\*\* HC3 focuses specifically on the US healthcare sector and includes indicators already observed by MedDefense, such as:



\- `meddefense-portal.com`

\- `medequip-supplies.net`

\- `meddefense-benefits.org`

\- `91.234.99.107`

\- `185.176.43.22`

\- `164.90.218.73`



HC3 also extends MedDefense's visibility by documenting later HEALTHBANE stages, including malware deployment and DNS-based exfiltration.



\### Limitations



HC3 reports at least 14 targeted healthcare organizations but has direct or partner visibility into only six. Only two of those organizations experienced all three documented stages.



Its visibility is therefore broader than MedDefense's, but still incomplete.



\### Bias / Visibility Constraints



HC3 has strong healthcare-sector visibility through partner organizations and sensors, but does not have complete visibility into every affected organization.



HC3 is also deliberately conservative about actor attribution. It has HIGH confidence in the campaign and observed stages but LOW confidence in attribution to a named actor.



\*\*Assessment:\*\* HC3 should be the primary source for confirmed healthcare-sector HEALTHBANE activity.



\---



\# 2.2 Acme Commercial Threat Intelligence Feed



\*\*Source:\*\* `commercial\_feed\_extract.json`



\*\*Source type:\*\* Commercial threat intelligence feed



\*\*Source reliability:\*\* \*\*B — Usually reliable\*\*



\*\*Information credibility:\*\* \*\*3 — Possibly true overall\*\*



\*\*Overall assessment:\*\* \*\*B3\*\*



\*\*Analytical confidence:\*\* \*\*MEDIUM overall\*\*, varying significantly by individual indicator.



\### Timeliness



\*\*High.\*\* The extract is dated 2026-04-26 and contains infrastructure active during the HEALTHBANE campaign.



\### Relevance to MedDefense



\*\*High\*\*, because the feed contains many HEALTHBANE indicators and overlaps with HC3 and MedDefense findings.



Examples of strongly corroborated entries include:



\- `meddefense-portal.com`

\- `healthbane-c2.net`

\- `91.234.99.107`

\- `51.38.42.191`



However, relevance varies significantly between individual indicators.



\### Limitations



The commercial feed explicitly states that indicators are automatically tagged by Acme's clustering engine and that analyst review is only sampled.



It contains several weak or noisy indicators. Examples include:



\- shared DigitalOcean infrastructure

\- Azure CDN infrastructure

\- Microsoft cloud infrastructure

\- Cloudflare infrastructure

\- indicators associated only through keyword similarity

\- indicators associated through ML clustering without external corroboration



Therefore, the complete commercial feed should \*\*not\*\* be treated as a blocklist.



\### Bias / Visibility Constraints



Acme uses its proprietary campaign label:



`VITALSCORE`



The feed warns that this label does not necessarily correspond to threat actor names used by external sources.



Its automated clustering also creates a risk of \*\*confirmation bias\*\*: technically similar or healthcare-themed infrastructure can be grouped into the same campaign even when direct evidence is weak.



\*\*Assessment:\*\* Useful for discovering additional infrastructure and pivot points, but individual indicators require validation before operational use.



\---



\# 2.3 Researcher Blog Analysis



\*\*Source:\*\* `researcher\_blog\_analysis.txt`



\*\*Source type:\*\* Open-source security research



\*\*Source reliability:\*\* \*\*B — Usually reliable\*\*



\*\*Information credibility:\*\* \*\*2 — Probably true\*\*



\*\*Overall assessment:\*\* \*\*B2\*\*



\*\*Analytical confidence:\*\* \*\*MEDIUM overall\*\*, with HIGH confidence for several technical findings.



\### Timeliness



\*\*High.\*\* The researcher published the analysis while the campaign was active and analyzed infrastructure and a recovered phishing kit associated with the operation.



\### Relevance to MedDefense



\*\*High.\*\*



The researcher provides technical information not fully available from the other sources, particularly the internal structure of the phishing kit.



The recovered `config.php` contained:



\- `OPS\_CONTACT`

\- `EXFIL\_ENDPOINT`

\- references to `healthbane-c2.net`



This helps connect the Stage 1 phishing infrastructure with later HEALTHBANE command-and-control activity.



\### Limitations



The researcher is a single independent analyst and does not have the same victim telemetry available to HC3 or MedDefense.



The researcher explicitly states that his attribution is based on:



\- tooling overlap

\- infrastructure overlap

\- historical campaign similarities



It is \*\*not\*\* based on:



\- victim telemetry

\- signals intelligence

\- insider reporting



The phishing-kit ZIP itself also has some uncertainty because the researcher cannot determine whether it is specific to the operator or supplied by a third-party kit vendor.



\### Bias / Visibility Constraints



The researcher tracks the suspected operator using his own private name:



`APT-MEDAGENT`



This creates potential attribution bias because historical similarities may lead the researcher to associate new activity with an actor he already tracks.



However, the researcher clearly states these limitations and gives his attribution only \*\*MEDIUM confidence\*\*.



\*\*Assessment:\*\* Very useful for technical analysis, infrastructure relationships, tooling, and campaign pivoting, but actor attribution should not be treated as confirmed.



\---



\# 2.4 MedDefense 4x00 Investigation



\*\*Source:\*\* `meddefens\_4x00\_findings.txt`



\*\*Source type:\*\* Internal investigation



\*\*Source reliability:\*\* \*\*A — Completely reliable for MedDefense observations\*\*



\*\*Information credibility:\*\* \*\*1 — Confirmed for directly observed evidence\*\*



\*\*Overall assessment:\*\* \*\*A1\*\*



\*\*Analytical confidence:\*\* \*\*HIGH\*\* for directly observed indicators; lower where the investigation explicitly identifies uncertainty.



\### Timeliness



\*\*Very high.\*\* This is direct internal incident evidence collected during the phishing activity.



\### Relevance to MedDefense



\*\*Very high.\*\*



This is the most directly relevant source because it describes activity observed against MedDefense employees and infrastructure.



It documents:



\- phishing emails received by employees

\- malicious domains and IPs

\- sender addresses

\- user interaction

\- SIEM evidence

\- authentication observations

\- MedDefense-specific indicators



\### Limitations



The 4x00 investigation explicitly did \*\*not\*\* include:



\- network packet analysis

\- endpoint forensics on `WS-NURSE-04`

\- follow-on authentication correlation



Therefore, the investigation concluded:



\*\*LIKELY CREDENTIAL EXPOSURE, NO CONFIRMED EXPLOITATION AT TIME OF REPORT\*\*



For example, the employee reported entering a password, but credential submission was not confirmed through packet evidence.



\### Bias / Visibility Constraints



MedDefense has excellent visibility into its own environment but limited visibility outside it.



This means it is strong evidence for questions such as:



> What happened at MedDefense?



but cannot independently establish:



> How large is the complete HEALTHBANE campaign?



or:



> Who operates HEALTHBANE?



MedDefense appropriately avoids assigning the campaign to a named threat actor.



\*\*Assessment:\*\* Highest priority for facts about what was directly observed inside MedDefense.



\---



\# 3. Source Comparison Matrix



| Assessment | HC3 | Commercial Feed | Researcher | MedDefense |

|---|---|---|---|---|

| \*\*Source type\*\* | Government advisory | Commercial feed | Open-source research | Internal investigation |

| \*\*Reliability\*\* | \*\*A\*\* | \*\*B\*\* | \*\*B\*\* | \*\*A\*\* |

| \*\*Information credibility\*\* | \*\*1\*\* | \*\*3\*\* | \*\*2\*\* | \*\*1\*\* |

| \*\*Admiralty rating\*\* | \*\*A1\*\* | \*\*B3\*\* | \*\*B2\*\* | \*\*A1\*\* |

| \*\*Timeliness\*\* | High | High | High | Very high |

| \*\*MedDefense relevance\*\* | Very high | High | High | Very high |

| \*\*Strongest area\*\* | Healthcare-sector campaign facts | IOC discovery/pivoting | Technical details | Direct internal evidence |

| \*\*Main limitation\*\* | Incomplete sector visibility | Automated clustering/noise | Limited victim telemetry | Internal visibility only |

| \*\*Attribution position\*\* | No confirmed actor | `VITALSCORE` | `APT-MEDAGENT` | No attribution |

| \*\*Attribution confidence\*\* | LOW | Variable/proprietary | MEDIUM | N/A |

| \*\*Overall analytical confidence\*\* | HIGH | MEDIUM | MEDIUM | HIGH |



\---



\# 4. Analytical Note — Attribution Conflict



The four sources do not provide a single confirmed threat actor attribution.



\### HC3 — `HEALTHBANE`



HC3 uses \*\*HEALTHBANE as a campaign designation\*\*, not as a confirmed actor identity.



HC3 explicitly states that attribution confidence is \*\*LOW\*\* and does not endorse the commercial `VITALSCORE` label.



Therefore:



> `HEALTHBANE` should currently be treated as the campaign name, not a confirmed threat actor.



\### Commercial Feed — `VITALSCORE`



Acme groups the activity under its proprietary:



`VITALSCORE`



However, Acme itself warns that its attribution label does not necessarily correspond to externally tracked threat actor names.



Some indicators assigned to the cluster also come from weak ML-based similarity.



Therefore:



> `VITALSCORE` should be treated as Acme's internal clustering label, not as confirmed attribution.



\### Researcher — `APT-MEDAGENT`



The researcher tracks the suspected operator as:



`APT-MEDAGENT`



He assesses the connection with \*\*MEDIUM confidence\*\*, based on similarities with earlier campaigns involving:



\- tooling

\- infrastructure

\- domain-registration patterns

\- phishing-kit structure



However, he explicitly states that the assessment is not supported by victim telemetry, signals intelligence, or insider reporting.



Therefore:



> `APT-MEDAGENT` is a reasonable analytical hypothesis, but it remains unconfirmed.



\### MedDefense



MedDefense does not assign the activity to a named actor.



This is appropriate because its investigation provides strong evidence about activity inside its environment but does not provide enough evidence to establish actor identity.



\### Current Analytical Position



The defensible position is:



> \*\*HEALTHBANE is the confirmed campaign designation. `VITALSCORE` and `APT-MEDAGENT` may describe overlapping activity, but the available intelligence does not establish that these labels represent the same threat actor.\*\*



Attribution should therefore remain \*\*unresolved\*\* until stronger corroborating evidence becomes available.



\---



\# 5. Weighting Recommendation



The sources should not all receive equal weight for every analytical question.



\### Confirmed healthcare-sector facts → Prioritize HC3



HC3 should be the primary source for the broader HEALTHBANE campaign because it combines information from multiple healthcare organizations, sensors, and external corroboration.



\*\*Weight: HIGH\*\*



\### MedDefense-specific facts → Prioritize MedDefense 4x00



For questions about what actually happened inside MedDefense, the internal investigation should receive the greatest weight because it contains direct organizational evidence.



\*\*Weight: HIGH\*\*



\### Technical details → Use the Researcher



The researcher provides valuable technical information about:



\- phishing-kit structure

\- configuration

\- infrastructure relationships

\- tooling fingerprints

\- potential pivot points



These details are particularly useful for threat hunting and further analysis.



\*\*Weight: MEDIUM-HIGH for technical findings\*\*



Attribution claims should remain \*\*MEDIUM confidence\*\*.



\### Additional IOC discovery → Use Commercial Feed Carefully



The commercial feed is useful for finding possible related infrastructure, but its additional indicators should not automatically become detection or blocking rules.



Indicators supported only by:



\- ML similarity

\- keywords

\- shared hosting

\- CDN/cloud infrastructure

\- the `VITALSCORE` label



should be validated before operational use.



\*\*Weight: MEDIUM overall; LOW for weakly clustered indicators\*\*



\---



\# 6. Handling Conflicting Claims



When sources disagree, the analyst should not simply choose one source.



Instead:



1\. \*\*Separate facts from assessments.\*\*

&#x20;  Directly observed malicious activity carries more weight than an attribution hypothesis.



2\. \*\*Check independent corroboration.\*\*

&#x20;  An indicator reported by HC3, MedDefense, and the researcher is stronger than one appearing only in an automated commercial cluster.



3\. \*\*Consider source visibility.\*\*

&#x20;  MedDefense knows its own environment best, while HC3 has broader healthcare-sector visibility.



4\. \*\*Keep attribution labels separate until proven equivalent.\*\*

&#x20;  `HEALTHBANE`, `VITALSCORE`, and `APT-MEDAGENT` should not automatically be merged.



5\. \*\*Record uncertainty explicitly.\*\*

&#x20;  Conflicting or incomplete evidence should result in MEDIUM or LOW confidence rather than unsupported certainty.



The final assessment should therefore prioritize \*\*direct observation and independent corroboration over source volume or proprietary attribution labels\*\*.

