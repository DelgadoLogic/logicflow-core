# Third-Party Open-Source Software & Font Notices

**Document Version**: 1.0.0  
**Effective Date / Last Updated**: October 13, 2026  
**Entity**: Delgado Creative Enterprises LLC d/b/a DelgadoLogic  
**Postal Address**: 6218 Georgia Avenue NW, Ste 1-698, Washington, DC 20011, USA  
**Applies To**: LogicFlow v1.0 Desktop Suite (`LogicFlow.exe`, `lf.exe`, `LogicFlowAgent.exe`), Website (`https://delgadologic.tech`), and Cloud Infrastructure

---

## 1. Overview

LogicFlow v1.0 is developed by **Delgado Creative Enterprises LLC d/b/a DelgadoLogic** and incorporates open-source libraries, runtime components, and redistributable fonts made available by their respective authors under permissive open-source licenses (`MIT`, `Apache-2.0`, `BSD-2-Clause`, `BSD-3-Clause`, `MIT-0`, `SIL Open Font License 1.1`, and `CC BY 4.0`).

This document provides the copyright notices, license attributions, and full license texts required by those components.

---

## 2. Shipped Desktop & CLI Dependencies (.NET 8.0)

The following NuGet packages and runtime libraries are linked or distributed with the LogicFlow v1.0 Windows Desktop Application (`LogicFlow.exe`), Command-Line Interface (`lf.exe`), Background Service (`LogicFlowAgent.exe`), and Core Assemblies (`DelgadoLogic.Core`, `LogicFlow.Guardian`, `LogicFlow.Sentinel`, `LogicFlow.Storage.Engine`, `LogicFlow.Lazarus`, `LogicFlow.Registry`, `LogicFlow.Native`, `OmniPulse`, `OmniCore.Engine`, `OmniLicense`, `OmniLicense.Commerce`, `LogicFlow.Scraper`, `LogicFlow.VoiceAgent`):

| Component / Package | Version | Target Assembly / Module | License | Copyright / Author | Upstream URL |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **.NET Runtime & Base Class Libraries** (`Microsoft.NETCore.App`, `Microsoft.WindowsDesktop.App.WPF`) | `8.0.x` | All Desktop, Service & CLI Assemblies | MIT | Copyright (c) .NET Foundation and Contributors | https://github.com/dotnet/runtime |
| **Microsoft.Extensions.*** (`Hosting`, `Hosting.WindowsServices`, `Logging`, `Logging.Abstractions`, `Logging.Console`, `Http`, `Configuration.Abstractions`) | `8.0.0` – `10.0.5` | `OmniService`, `LogicFlow.Dashboard`, `LogicFlow.CLI`, `OmniCore.Engine`, `DelgadoLogic.Core`, `OmniLicense` | MIT | Copyright (c) .NET Foundation and Contributors | https://github.com/dotnet/runtime |
| **System.Management**, **System.Diagnostics.PerformanceCounter**, **System.ServiceProcess.ServiceController**, **System.Net.Http.Json**, **System.Text.Json** | `8.0.0` – `8.0.5` | `LogicFlow.Guardian`, `LogicFlow.Sentinel`, `LogicFlow.Lazarus`, `OmniPulse`, `OmniService`, `OmniLicense` | MIT | Copyright (c) .NET Foundation and Contributors | https://github.com/dotnet/runtime |
| **WPF-UI (`Wpf.Ui`)** | `4.3.0` | `LogicFlow.Dashboard` (`LogicFlow.exe`) | MIT | Copyright (c) 2021–2025 Leszek Pomianowski and WPF UI Contributors | https://github.com/lepoco/wpfui |
| **BouncyCastle.Cryptography** | `2.6.2` | `DelgadoLogic.Core`, `OmniCore.Engine` | MIT | Copyright (c) 2000–2025 The Legion of the Bouncy Castle Inc. | https://www.bouncycastle.org/csharp/ |
| **Blake3** (`Blake3.NET`) | `3.0.2` | `LogicFlow.Storage.Engine` | BSD-2-Clause (wrapper) / CC0-1.0 or Apache-2.0 (native BLAKE3) | Copyright (c) 2020–2025 Alexandre Mutel (xoofx); Official BLAKE3 Team (Jack O'Connor, Jean-Philippe Aumasson, Samuel Neves, Zooko Wilcox-O'Hearn) | https://github.com/xoofx/Blake3.NET |
| **ZstdSharp.Port** | `0.8.4` | `LogicFlow.Storage.Engine` | MIT (C# port of Meta Zstandard BSD-3-Clause) | Copyright (c) 2021–2025 Oleg Stepanischev; Zstandard Copyright (c) Meta Platforms, Inc. and affiliates | https://github.com/oleg-st/ZstdSharp |
| **HtmlAgilityPack** | `1.12.4` | `LogicFlow.Scraper` | MIT | Copyright (c) ZZZ Projects Inc. | https://html-agility-pack.net/ |
| **PayPalServerSdk** | `2.2.0` | `OmniLicense.Commerce` | MIT | Copyright (c) PayPal, Inc. | https://github.com/paypal/PayPal-DotNet-Server-SDK |
| **NAudio** (`NAudio`, `NAudio.Core`, `NAudio.Wasapi`, `NAudio.WinMM`, `NAudio.Asio`, `NAudio.Midi`) | `2.2.1` | `LogicFlow.VoiceAgent` (`LogicFlow.VoiceAgent.dll`, shipped with `LogicFlow.Dashboard`) | MIT | Copyright (c) 2020 Mark Heath & NAudio Contributors | https://github.com/naudio/NAudio |

### 2.1 Optional User-Downloaded Local AI Components (`GemmaAiEngine` — Not Bundled in Installer)

Nothing below is bundled inside `LogicFlowSetup.exe` or downloaded automatically. If you explicitly click **Download Local Model** in **Settings → AI Engine**, `GemmaAiEngine` downloads and SHA-256-verifies the following open-source components into `%LOCALAPPDATA%\LogicFlow\AI\`:

| Component | Pinned Release / Artifact | License | Copyright / Author | Upstream URL |
| :--- | :--- | :--- | :--- | :--- |
| **llama.cpp (`llama-server.exe`)** | Release `b12283` (`llama-b12283-bin-win-vulkan-x64.zip`) | MIT | Copyright (c) 2023–2026 Georgi Gerganov and `llama.cpp` contributors | https://github.com/ggml-org/llama.cpp |
| **Google Gemma 4 E2B (`gemma-4-E2B-it`)** | `google_gemma-4-E2B-it-Q4_K_M.gguf` (quantized GGUF weights) | Apache-2.0 | Copyright (c) 2025–2026 Google LLC (quantized GGUF packaging by `bartowski`) | https://huggingface.co/bartowski/google_gemma-4-E2B-it-GGUF |

> **Note on Internal Test Frameworks**:
> - Test-only frameworks (`xunit` `2.5.3` [Apache-2.0], `xunit.runner.visualstudio` `2.5.3` [Apache-2.0], `Moq` `4.20.72` [BSD-3-Clause], `coverlet.collector` `6.0.0` [MIT], and `Microsoft.NET.Test.Sdk` `17.8.0` [MIT]) are used solely during internal automated builds (`LogicFlow.Tests`) and are not distributed to end users.

---

## 3. Bundled & Self-Hosted Fonts and Icon Assets

| Font / Asset Family | Files / Distribution | License | Copyright / Foundry | Source URL |
| :--- | :--- | :--- | :--- | :--- |
| **Inter** | `Inter_18pt-*.ttf` / self-hosted `.woff2` (`Assets/Fonts/` & `delgadologic.tech/fonts/`) | SIL Open Font License 1.1 | Copyright (c) 2016–2024 The Inter Project Authors (Rasmus Andersson) | https://rsms.me/inter/ |
| **Outfit** | `Outfit[wght].ttf` (`Assets/Fonts/Outfit/`) | SIL Open Font License 1.1 | Copyright (c) 2021 The Outfit Project Authors (Rodrigo Fuenzalida, On Brand Investments Pty Ltd) | https://github.com/Outfitio/Outfit-Fonts |
| **JetBrains Mono** | Self-hosted `.woff2` (`delgadologic.tech/fonts/`) | SIL Open Font License 1.1 | Copyright (c) 2020 JetBrains s.r.o. | https://www.jetbrains.com/lp/mono/ |
| **Font Awesome Free** | `6.5.1` Self-hosted (`delgadologic.tech/fonts/`) | Icons: CC BY 4.0; Fonts: SIL OFL 1.1; Code: MIT | Copyright (c) Fonticons, Inc. | https://fontawesome.com/license/free |

---

## 4. Website & Cloud Backend Open-Source Dependencies

The `delgadologic.tech` website (`Website/site`), licensing Cloud Functions (`Website/functions`), and telemetry ingestion service (`Products/LogicFlow/Infrastructure/telemetry-ingest`) use the following open-source JavaScript/Node.js packages:

### 4.1 Website Frontend (`Website/site`)
- **React & React DOM** (`^18.3.1`) — MIT License — Copyright (c) Meta Platforms, Inc. and affiliates.
- **React Router DOM** (`^6.28.0`) — MIT License — Copyright (c) Remix Software Inc.
- **React Helmet Async** (`^3.0.0`) — Apache-2.0 License — Copyright (c) Scott Taylor and contributors.
- **Framer Motion** (`^12.38.0`) — MIT License — Copyright (c) Framer B.V.
- **Lenis** (`^1.3.21`) — MIT License — Copyright (c) darkroom.engineering.
- **tsParticles (`@tsparticles/react` `^3.0.0`, `@tsparticles/slim` `^3.9.1`)** — MIT License — Copyright (c) Matteo Bruni.
- **Firebase JS SDK (`firebase` `^12.11.0`)** — Apache-2.0 License — Copyright (c) Google LLC.
- **Vite (`vite` `^6.0.5`)** — MIT License — Copyright (c) Evan You and Vite contributors.

### 4.2 Cloud Functions & Telemetry Ingest (`Website/functions` & `telemetry-ingest`)
- **firebase-admin** (`^12.0.0`) — Apache-2.0 License — Copyright (c) Google LLC.
- **firebase-functions** (`^5.0.0`) — MIT License — Copyright (c) Google LLC.
- **stripe** (`^21.0.1`) — MIT License — Copyright (c) Stripe, Inc.
- **nodemailer** (`^6.9.0`) — MIT-0 License — Copyright (c) Andris Reinman.
- **node-fetch** (`^2.7.0`) — MIT License — Copyright (c) Matthew Andrews & contributors.
- **@google-cloud/storage** (`^7.14.0`) — Apache-2.0 License — Copyright (c) Google LLC.
- **ajv** (`^8.17.1`) & **ajv-formats** (`^3.0.1`) — MIT License — Copyright (c) Evgeny Poberezkin.

---

## 5. Full License Texts

### 5.1 The MIT License (MIT)

Applies to: `.NET Runtime / Microsoft.Extensions.* / System.*`, `WPF-UI`, `BouncyCastle.Cryptography`, `ZstdSharp.Port`, `HtmlAgilityPack`, `PayPalServerSdk`, `NAudio`, optional `llama.cpp` (`llama-server.exe`), `React`, `React Router`, `Framer Motion`, `Lenis`, `tsParticles`, `Vite`, `firebase-functions`, `stripe`, `node-fetch`, `ajv`, `ajv-formats`.

```text
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

### 5.2 BSD 2-Clause "Simplified" License

Applies to: `Blake3.NET` (`Blake3` `3.0.2`, Copyright (c) 2020–2025 Alexandre Mutel).

```text
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

---

### 5.3 BSD 3-Clause "New" or "Revised" License

Applies to: Upstream Meta Zstandard algorithm concepts ported in `ZstdSharp.Port` (Copyright (c) Meta Platforms, Inc. and affiliates).

```text
Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

 * Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

 * Neither the name Meta Platforms, Inc. nor the names of its contributors may
   be used to endorse or promote products derived from this software without
   specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

---

### 5.4 Apache License, Version 2.0

Applies to: Native `BLAKE3` implementation, optional `Google Gemma 4 E2B` (`gemma-4-E2B-it` GGUF model weights), `firebase`, `firebase-admin`, `@google-cloud/storage`, `react-helmet-async`.

```text
                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
```

---

### 5.5 SIL Open Font License, Version 1.1 (OFL-1.1)

Applies to: `Inter`, `Outfit`, `JetBrains Mono`, and `Font Awesome Free` font files.

```text
SIL OPEN FONT LICENSE Version 1.1 - 26 February 2007

PREAMBLE
The goals of the Open Font License (OFL) are to stimulate worldwide
development of collaborative font projects, to support the font creation
efforts of academic and linguistic communities, and to provide a free and
open framework in which fonts may be shared and improved in partnership
with others.

The OFL allows the licensed fonts to be used, studied, modified and
redistributed freely as long as they are not sold by themselves. The
fonts, including any derivative works, can be bundled, embedded,
redistributed and/or sold with any software provided that any reserved
names are not used by derivative works. The fonts and derivatives,
however, cannot be released under any other type of license. The
requirement for fonts to remain under this license does not apply
to any document created using the fonts or their derivatives.

PERMISSION & CONDITIONS
Permission is hereby granted, free of charge, to any person obtaining
a copy of the Font Software, to use, study, copy, merge, embed, modify,
redistribute, and sell modified and unmodified copies of the Font
Software, subject to the following conditions:

1) Neither the Font Software nor any of its individual components,
in Original or Modified Versions, may be sold by itself.

2) Original or Modified Versions of the Font Software may be bundled,
redistributed and/or sold with any software, provided that each copy
contains the above copyright notice and this license. These can be
included either as stand-alone text files, human-readable headers or
in the appropriate machine-readable metadata fields within text or
binary files as long as those fields can be easily viewed by the user.

3) No Modified Version of the Font Software may use the Reserved Font
Name(s) unless explicit written permission is granted by the corresponding
Copyright Holder. This restriction only applies to the primary font name as
presented to the users.

4) The name(s) of the Copyright Holder(s) or the Author(s) of the Font
Software shall not be used to promote, endorse or advertise any
Modified Version, except to acknowledge the contribution(s) of the
Copyright Holder(s) and the Author(s) or with their explicit written
permission.

5) The Font Software, modified or unmodified, in part or in whole,
must be distributed entirely under this license, and must not be
distributed under any other license. The requirement for fonts to
remain under this license does not apply to any document created
using the Font Software.

TERMINATION
This license becomes null and void if any of the above conditions are
not met.

DISCLAIMER
THE FONT SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO ANY WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT
OF COPYRIGHT, PATENT, TRADEMARK, OR OTHER RIGHT. IN NO EVENT SHALL THE
COPYRIGHT HOLDER BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
INCLUDING ANY GENERAL, SPECIAL, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL
DAMAGES, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF THE USE OR INABILITY TO USE THE FONT SOFTWARE OR FROM
OTHER DEALINGS IN THE FONT SOFTWARE.
```
