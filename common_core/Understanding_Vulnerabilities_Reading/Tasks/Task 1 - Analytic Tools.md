<== [[Task 0 - Vulnerability in Cyber Security]] - [[Task 2 - Prevent Injection]] =>


**Instructions:**

1. **Introduction to Static and Dynamic Analysis Tools:**

- What is static analysis, and how does it differ from dynamic analysis?
- Why are these tools essential for software security?
- How do static and dynamic analysis tools contribute to effective security practices?

1. **Historical Context:**
    - Briefly explore the origins of static and dynamic analysis tools.
    - Explain how the role of these tools has evolved with advancements in software development and security practices.
2. **Types of Analysis Tools Explained:**

- Discuss the significance and impact of static and dynamic analysis tools in software security.
- Cover specific examples and scenarios where each tool is most effective.

1. **The Impact of Analysis Tools on Software Security:**

- Discuss the relevance and application of static and dynamic analysis tools in safeguarding software systems.
- Cover aspects such as integration into development workflows, effectiveness in detecting different types of vulnerabilities, and how they complement each other.

1. **Conclusion and Teaser:**

- Conclude by summarizing the key differences and benefits of static and dynamic analysis tools.


1. When developing an application [Software], there is a standard called: SDLC[^1] which controls the production cycle of the software. For creating a more secure and robust application, we need to analyse the code in two phases of the SDLC. First, when the application is in development. Here we have static analysis, which means the source code is being inspected and reviewed based on standards, and flaws like syntax errors, left hardcoded credentials, SQL injection risks through data flows and also finding insecure cryptographic implementations are addressed. On the other hand, another matter is dynamic analysis, which controls the behavior of the software when it is in production. In this phase application is being monitored for detecting authentication and authorization flaws, identify runtime injection vulnerabilities, discover memory corruption issues and the application's behaviour under unexpected input.

[^1]: Software Development Life Cycle


# Static vs Dynamic Analysis: Checking Software Before and After It Runs

When we develop software, we usually follow a process called the **Software Development Life Cycle**, or **SDLC**. The SDLC is basically the journey of software: planning, designing, building, testing, releasing, and maintaining it. But here is the important cybersecurity question:

**At what point should we check if the software is secure?**

The simple answer is: **more than once.**

Security should not be something we only think about at the end. If we wait until the application is already live, a small mistake in the code can become a real weakness that attackers may use.

This is where two important security approaches come in:

🔍 **Static Analysis**  
⚙️ **Dynamic Analysis**

They both help us find vulnerabilities, but they do it in different ways.

## 🔍 Static Analysis: Checking the Code Before It Runs

Static analysis means checking the source code, binary code, or design of an application **without running the program**.

It is like reading the blueprint of a building before construction is finished. You are not walking inside the building yet, but you can already see if something looks unsafe.

In software security, static analysis can help find problems such as:

- insecure coding patterns
- possible SQL injection risks
- hardcoded credentials    
- weak input validation    
- unsafe cryptographic implementations
- memory-related issues in some programming languages

The main advantage is that static analysis can be done early in the SDLC, while the software is still being developed. That matters because *fixing a security issue early is usually easier, cheaper, and safer* than fixing it after the application is already in production.

For example, imagine a developer writes a login function that sends user input directly into a database query. A static analysis tool may detect that this pattern could lead to SQL injection before the application is ever deployed.

That is the power of static analysis: it helps catch problems before they become real incidents.

## ⚙️ Dynamic Analysis: Checking the Software While It Runs

Dynamic analysis is different.

Instead of only looking at the code, dynamic analysis checks how the application behaves **while it is running**.

This is like testing the building after the doors are open: checking the locks, cameras, alarms, emergency exits, and how the system reacts when something unexpected happens.

Dynamic analysis can help detect issues such as:

- authentication problems
- authorization flaws
- runtime injection vulnerabilities
- memory corruption
- insecure behavior under unexpected input
- weaknesses that only appear during execution

For example, a web application might look fine in the source code, but when a user sends unexpected input, the application may crash, expose sensitive information, or behave in an unsafe way.

Dynamic analysis is useful because some vulnerabilities only become visible when the software is actually running. This is why methods like penetration testing and fuzzing are important. They help security testers interact with the application like a real user, or sometimes like an attacker, to see how the system responds.

## 🧩 So, Which One Is Better?

The answer is: **neither one is enough alone.**

Static analysis is strong because it can check code early and cover a large part of the codebase. But it also has limitations. It may produce false positives, meaning it warns about something that is not actually dangerous. It may also miss problems that only appear when the software runs.

Dynamic analysis is strong because it shows how the application behaves in real conditions. But it also has limitations. It needs a running environment, proper test cases, and sometimes more time and expertise. It may also miss parts of the code that are not triggered during testing.

So, the best approach is to use both.

## 🔐 Why They Matter for Software Security

Modern software is complex. Applications use APIs, databases, cloud services, third-party libraries, authentication systems, and user input from many different places. Because of this, security testing cannot depend on only one method.

**Static analysis** helps developers find issues early.

**Dynamic analysis** helps security teams confirm how serious those issues are in real-world behavior.

Together, they give a more complete picture of application security. This is especially important for companies because vulnerabilities are not only technical problems. They can lead to data breaches, financial loss, legal problems, and damage to user trust.

## 🚀 How These Tools Fit Into Modern Development

Today, many teams try to integrate security tools directly into their development workflow.

**For example:**

- A static analysis tool can run when a developer pushes new code.

- A dynamic analysis tool can test the application in a staging environment before release.

Security becomes part of the development process instead of something separate at the end. This idea is closely connected to secure software development: finding and fixing problems as early as possible, while still testing the application in realistic conditions.

## 🧠 Final Thought

Static and dynamic analysis are not just tools. They are two different ways of thinking about software security.

Static analysis asks:

**“What could go wrong in the code?”**

Dynamic analysis asks:

**“What actually happens when the software runs?”**

A secure application needs both questions.

Because in cybersecurity, it is not enough for software to work.

It also needs to behave safely when something goes wrong.

---

### Sources

1. NIST, Secure Software Development Framework (SSDF) Version 1.1, SP 800-218, 2022.
2. OWASP, Source Code Analysis Tools / Static Application Security Testing (SAST).
3. OWASP, Dynamic Application Security Testing (DAST), OWASP DevSecOps Guideline.
4. Nguyen Thanh Cong, Le Huy Toan, Ta Minh Thanh, “An overview of static and dynamic analysis in application security testing,” Journal of Military Science and Technology, 99, 2024.
5. Brian Mweu and John Ndia, “Static Analysis Techniques for Secure Software: A Systematic Review,” Journal of Cyber Security, Tech Science Press, 2025.
6. Stephen C. Johnson, “Lint, a C Program Checker,” Bell Labs, 1978.
7. Nicholas Nethercote and Julian Seward, “Valgrind: A Framework for Heavyweight Dynamic Binary Instrumentation,” ACM PLDI, 2007.