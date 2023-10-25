"use strict";(self.webpackChunkwebsite=self.webpackChunkwebsite||[]).push([[9212],{3905:(e,t,n)=>{n.d(t,{Zo:()=>u,kt:()=>h});var o=n(7294);function i(e,t,n){return t in e?Object.defineProperty(e,t,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[t]=n,e}function a(e,t){var n=Object.keys(e);if(Object.getOwnPropertySymbols){var o=Object.getOwnPropertySymbols(e);t&&(o=o.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),n.push.apply(n,o)}return n}function r(e){for(var t=1;t<arguments.length;t++){var n=null!=arguments[t]?arguments[t]:{};t%2?a(Object(n),!0).forEach((function(t){i(e,t,n[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(n)):a(Object(n)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(n,t))}))}return e}function s(e,t){if(null==e)return{};var n,o,i=function(e,t){if(null==e)return{};var n,o,i={},a=Object.keys(e);for(o=0;o<a.length;o++)n=a[o],t.indexOf(n)>=0||(i[n]=e[n]);return i}(e,t);if(Object.getOwnPropertySymbols){var a=Object.getOwnPropertySymbols(e);for(o=0;o<a.length;o++)n=a[o],t.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(i[n]=e[n])}return i}var l=o.createContext({}),c=function(e){var t=o.useContext(l),n=t;return e&&(n="function"==typeof e?e(t):r(r({},t),e)),n},u=function(e){var t=c(e.components);return o.createElement(l.Provider,{value:t},e.children)},p="mdxType",d={inlineCode:"code",wrapper:function(e){var t=e.children;return o.createElement(o.Fragment,{},t)}},m=o.forwardRef((function(e,t){var n=e.components,i=e.mdxType,a=e.originalType,l=e.parentName,u=s(e,["components","mdxType","originalType","parentName"]),p=c(n),m=i,h=p["".concat(l,".").concat(m)]||p[m]||d[m]||a;return n?o.createElement(h,r(r({ref:t},u),{},{components:n})):o.createElement(h,r({ref:t},u))}));function h(e,t){var n=arguments,i=t&&t.mdxType;if("string"==typeof e||i){var a=n.length,r=new Array(a);r[0]=m;var s={};for(var l in t)hasOwnProperty.call(t,l)&&(s[l]=t[l]);s.originalType=e,s[p]="string"==typeof e?e:i,r[1]=s;for(var c=2;c<a;c++)r[c]=n[c];return o.createElement.apply(null,r)}return o.createElement.apply(null,n)}m.displayName="MDXCreateElement"},6954:(e,t,n)=>{n.r(t),n.d(t,{assets:()=>l,contentTitle:()=>r,default:()=>p,frontMatter:()=>a,metadata:()=>s,toc:()=>c});var o=n(7462),i=(n(7294),n(3905));const a={title:"Contributing"},r=void 0,s={unversionedId:"contributing",id:"version-v0.4.x/contributing",title:"Contributing",description:"Welcome! We are very happy to accept community contributions to the project, whether through filing issues or code in the form of Pull Requests. Please note that by participating in this project, you agree to abide by the Code of Conduct, as well as the terms of the Developer Certificate of Origin.",source:"@site/versioned_docs/version-v0.4.x/contributing.md",sourceDirName:".",slug:"/contributing",permalink:"/copacetic/website/v0.4.x/contributing",draft:!1,tags:[],version:"v0.4.x",frontMatter:{title:"Contributing"},sidebar:"sidebar",previous:{title:"FAQ",permalink:"/copacetic/website/v0.4.x/faq"},next:{title:"Code of Conduct",permalink:"/copacetic/website/v0.4.x/code-of-conduct"}},l={},c=[{value:"Bi-Weekly Community Meeting",id:"bi-weekly-community-meeting",level:2},{value:"Slack",id:"slack",level:2},{value:"Contributing Issues",id:"contributing-issues",level:2},{value:"Contributing Code",id:"contributing-code",level:2},{value:"Getting Started",id:"getting-started",level:3},{value:"Visual Studio Code Development Container",id:"visual-studio-code-development-container",level:3},{value:"Prerequisites",id:"prerequisites",level:4},{value:"Personalizing user settings in a dev container",id:"personalizing-user-settings-in-a-dev-container",level:4},{value:"Tests",id:"tests",level:3},{value:"Pull Requests",id:"pull-requests",level:3},{value:"Developer Certificate of Origin (DCO)",id:"developer-certificate-of-origin-dco",level:2},{value:"I didn&#39;t sign my commit, now what?",id:"i-didnt-sign-my-commit-now-what",level:3},{value:"Code of Conduct",id:"code-of-conduct",level:2}],u={toc:c};function p(e){let{components:t,...n}=e;return(0,i.kt)("wrapper",(0,o.Z)({},u,n,{components:t,mdxType:"MDXLayout"}),(0,i.kt)("p",null,"Welcome! We are very happy to accept community contributions to the project, whether through ",(0,i.kt)("a",{parentName:"p",href:"#contributing-issues"},"filing issues")," or ",(0,i.kt)("a",{parentName:"p",href:"#contributing-code"},"code")," in the form of ",(0,i.kt)("a",{parentName:"p",href:"#pull-requests"},"Pull Requests"),". Please note that by participating in this project, you agree to abide by the ",(0,i.kt)("a",{parentName:"p",href:"/copacetic/website/v0.4.x/code-of-conduct"},"Code of Conduct"),", as well as the terms of the ",(0,i.kt)("a",{parentName:"p",href:"#developer-certificate-of-origin-dco"},"Developer Certificate of Origin"),"."),(0,i.kt)("h2",{id:"bi-weekly-community-meeting"},"Bi-Weekly Community Meeting"),(0,i.kt)("p",null,"A great way to get started is to join our bi-weekly community meeting. The meeting is held every other Monday from 1:30pm PT - 2:15pm PT. You can find the agenda and links to join ",(0,i.kt)("a",{parentName:"p",href:"https://docs.google.com/document/d/1QdskbeCtgKcdWYHI6EXkLFxyzTCyVT6e8MgB3CaAhWI/edit?usp=sharing"},"here")),(0,i.kt)("h2",{id:"slack"},"Slack"),(0,i.kt)("p",null,"To discuss issues with Copa, features, or development, you can join the ",(0,i.kt)("inlineCode",{parentName:"p"},"#copa")," channel on the ",(0,i.kt)("a",{parentName:"p",href:"https://communityinviter.com/apps/opencontainers/join-the-oci-community"},"OCI Slack"),"."),(0,i.kt)("h2",{id:"contributing-issues"},"Contributing Issues"),(0,i.kt)("p",null,"Before opening any new issues, please search our ",(0,i.kt)("a",{parentName:"p",href:"https://github.com/project-copacetic/copacetic/issues"},"existing GitHub issues")," to check if your bug or suggestion has already been filed. If such an issue already exists, we recommend adding your comments and perspective to that existing issue instead."),(0,i.kt)("p",null,"When opening an issue, please select the most appropriate template for what you're contributing:"),(0,i.kt)("ul",null,(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("strong",{parentName:"li"},"Bug Report:")," If you would like to report the project or tool behaving in unexpected ways."),(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("strong",{parentName:"li"},"Documentation Improvement:")," If you have corrections or improvements to the project's documents, be they typos, factual errors, or missing content."),(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("strong",{parentName:"li"},"Request:")," If you have a feature request, suggestion, or a even a design proposal to review."),(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("strong",{parentName:"li"},"Question:")," If you would like to ask the maintainers a question about the project.")),(0,i.kt)("h2",{id:"contributing-code"},"Contributing Code"),(0,i.kt)("h3",{id:"getting-started"},"Getting Started"),(0,i.kt)("p",null,"Follow the instructions to either:"),(0,i.kt)("ul",null,(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("a",{parentName:"li",href:"/copacetic/website/v0.4.x/installation"},"Setup your dev environment to build copa"),"."),(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("a",{parentName:"li",href:"#visual-studio-code-development-container"},"Use the copa development container")," in ",(0,i.kt)("a",{parentName:"li",href:"https://code.visualstudio.com/"},"Visual Studio Code"),".")),(0,i.kt)("p",null,"For an overview of the project components, refer to the ",(0,i.kt)("a",{parentName:"p",href:"/copacetic/website/v0.4.x/design"},"copa design")," document."),(0,i.kt)("h3",{id:"visual-studio-code-development-container"},"Visual Studio Code Development Container"),(0,i.kt)("p",null,(0,i.kt)("a",{parentName:"p",href:"https://code.visualstudio.com/"},"VSCode")," supports development in a containerized environment through its ",(0,i.kt)("a",{parentName:"p",href:"https://code.visualstudio.com/docs/remote/containers"},"Remote - Container extension"),". This folder provides a development container which encapsulates the dependencies specified in the ",(0,i.kt)("a",{parentName:"p",href:"/copacetic/website/v0.4.x/installation"},"instructions to build and run copa"),"."),(0,i.kt)("h4",{id:"prerequisites"},"Prerequisites"),(0,i.kt)("ol",null,(0,i.kt)("li",{parentName:"ol"},(0,i.kt)("a",{parentName:"li",href:"https://docs.docker.com/get-docker/"},"Docker"),(0,i.kt)("blockquote",{parentName:"li"},(0,i.kt)("p",{parentName:"blockquote"},"For Windows users, enabling ",(0,i.kt)("a",{parentName:"p",href:"https://docs.docker.com/docker-for-windows/wsl/"},"WSL2 back-end integration with Docker")," is recommended."))),(0,i.kt)("li",{parentName:"ol"},(0,i.kt)("a",{parentName:"li",href:"https://code.visualstudio.com/"},"Visual Studio Code")),(0,i.kt)("li",{parentName:"ol"},(0,i.kt)("a",{parentName:"li",href:"https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers"},"Visual Studio Code Remote - Containers extension"))),(0,i.kt)("blockquote",null,(0,i.kt)("p",{parentName:"blockquote"},(0,i.kt)("strong",{parentName:"p"},"\u26a0 If running via Docker Desktop for Windows")),(0,i.kt)("p",{parentName:"blockquote"},"Note that the ",(0,i.kt)("a",{parentName:"p",href:"https://code.visualstudio.com/remote/advancedcontainers/add-nonroot-user"},"mounted workspace files appear owned by ",(0,i.kt)("inlineCode",{parentName:"a"},"root"))," in the dev container, which will cause ",(0,i.kt)("inlineCode",{parentName:"p"},"git")," commands to fail with a ",(0,i.kt)("inlineCode",{parentName:"p"},"fatal: detected dubious ownership in a repository")," error due to ",(0,i.kt)("a",{parentName:"p",href:"https://git-scm.com/docs/git-config/2.35.2#Documentation/git-config.txt-safedirectory"},"safe.directory")," checks. This can be addressed by changing the mapped ownership of the workspace files in the dev container to the ",(0,i.kt)("inlineCode",{parentName:"p"},"vscode")," user:"),(0,i.kt)("pre",{parentName:"blockquote"},(0,i.kt)("code",{parentName:"pre",className:"language-bash"},"sudo chown -R vscode:vscode /workspace/copacetic\n"))),(0,i.kt)("h4",{id:"personalizing-user-settings-in-a-dev-container"},"Personalizing user settings in a dev container"),(0,i.kt)("p",null,"VSCode supports applying your user settings, such as your ",(0,i.kt)("inlineCode",{parentName:"p"},".gitconfig"),", to a dev container through the use of ",(0,i.kt)("a",{parentName:"p",href:"https://code.visualstudio.com/docs/remote/containers#_personalizing-with-dotfile-repositories"},"dotfiles repositories"),". This can be done through your own VSCode ",(0,i.kt)("inlineCode",{parentName:"p"},"settings.json")," file without changing the dev container image or configuration."),(0,i.kt)("h3",{id:"tests"},"Tests"),(0,i.kt)("p",null,"Once you can successfully ",(0,i.kt)("inlineCode",{parentName:"p"},"make")," the project, any code contributions should also successfully:"),(0,i.kt)("ul",null,(0,i.kt)("li",{parentName:"ul"},"Pass unit tests via ",(0,i.kt)("inlineCode",{parentName:"li"},"make test"),"."),(0,i.kt)("li",{parentName:"ul"},"Lint cleanly via ",(0,i.kt)("inlineCode",{parentName:"li"},"make lint"),".")),(0,i.kt)("p",null,"Pull requests will also be expected to pass the PR functional tests specified by ",(0,i.kt)("inlineCode",{parentName:"p"},".github/workflows/build.yml"),"."),(0,i.kt)("h3",{id:"pull-requests"},"Pull Requests"),(0,i.kt)("p",null,"If you'd like to start contributing code to the project, you can search for ",(0,i.kt)("a",{parentName:"p",href:"https://github.com/project-copacetic/copacetic/labels/good%20first%20issue"},"issues with the ",(0,i.kt)("inlineCode",{parentName:"a"},"good first issue")," label"),". Other kinds of PR contributions we would look for include:"),(0,i.kt)("ul",null,(0,i.kt)("li",{parentName:"ul"},"Fixes for bugs and other correctness issues."),(0,i.kt)("li",{parentName:"ul"},"Docs and other content improvements (e.g. samples)."),(0,i.kt)("li",{parentName:"ul"},"Extensions to support parsing new scanning report formats."),(0,i.kt)("li",{parentName:"ul"},"Extensions to support patching images based on new distros or using new package managers.")),(0,i.kt)("p",null,"For any changes that may involve significant refactoring or development effort, we suggest that you file an issue to discuss the proposal with the maintainers first as it is unlikely that we will accept large PRs without prior discussion that have:"),(0,i.kt)("ul",null,(0,i.kt)("li",{parentName:"ul"},"Architectural changes (e.g. breaking interfaces or violations of ",(0,i.kt)("a",{parentName:"li",href:"/copacetic/website/v0.4.x/design"},"this project's design tenets"),")."),(0,i.kt)("li",{parentName:"ul"},"Unsolicited features that significantly expand the functional scope of the tool.")),(0,i.kt)("p",null,"Pull requests should be submitted from your fork of the project with the PR template filled out. This project uses the ",(0,i.kt)("a",{parentName:"p",href:"https://github.com/angular/angular/blob/main/CONTRIBUTING.md#-commit-message-format"},"Angular commit message format")," for automated changelog generation, so it's helpful to be familiar with it as the maintainers will need to ensure adherence to it on accepting PRs."),(0,i.kt)("p",null,"We suggest:"),(0,i.kt)("ul",null,(0,i.kt)("li",{parentName:"ul"},"Use the standard header format of ",(0,i.kt)("inlineCode",{parentName:"li"},'"<type>: <short summary>"')," where the ",(0,i.kt)("inlineCode",{parentName:"li"},"<type>")," is one of the following:",(0,i.kt)("ul",{parentName:"li"},(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("strong",{parentName:"li"},"build:")," Changes that affect the build system or external dependencies"),(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("strong",{parentName:"li"},"ci:")," Changes to the GitHub workflows and configurations"),(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("strong",{parentName:"li"},"docs:")," Documentation only changes"),(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("strong",{parentName:"li"},"feat:")," A new feature"),(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("strong",{parentName:"li"},"fix:")," A bug fix"),(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("strong",{parentName:"li"},"perf:")," A code change that improves performance"),(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("strong",{parentName:"li"},"refactor:")," A code change that neither fixes a bug nor adds a feature"),(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("strong",{parentName:"li"},"test:")," Adding missing tests or correcting existing tests"))),(0,i.kt)("li",{parentName:"ul"},"Use a ",(0,i.kt)("a",{parentName:"li",href:"https://tbaggery.com/2008/04/19/a-note-about-git-commit-messages.html"},"concise, imperative description")," of the changes included in the ",(0,i.kt)("inlineCode",{parentName:"li"},"<short summary>")," of the header, the body of the PR, and generally in your commit messages."),(0,i.kt)("li",{parentName:"ul"},"Use ",(0,i.kt)("a",{parentName:"li",href:"https://docs.github.com/en/get-started/writing-on-github/working-with-advanced-formatting/using-keywords-in-issues-and-pull-requests"},"GitHub keywords")," in the footer of your PR description, such as ",(0,i.kt)("inlineCode",{parentName:"li"},"closes")," to automatically close issues the PR intends to address.")),(0,i.kt)("h2",{id:"developer-certificate-of-origin-dco"},"Developer Certificate of Origin (DCO)"),(0,i.kt)("p",null,"The ",(0,i.kt)("a",{parentName:"p",href:"https://wiki.linuxfoundation.org/dco"},"Developer Certificate of Origin")," (DCO) is a lightweight way for contributors to certify that they wrote or otherwise have the right to submit the code they are contributing to the project. Here is the ",(0,i.kt)("a",{parentName:"p",href:"https://developercertificate.org/"},"full text of the DCO"),", reformatted for readability:"),(0,i.kt)("blockquote",null,(0,i.kt)("p",{parentName:"blockquote"},"By making a contribution to this project, I certify that:"),(0,i.kt)("p",{parentName:"blockquote"},"(a) The contribution was created in whole or in part by me and I\nhave the right to submit it under the open source license\nindicated in the file; or"),(0,i.kt)("p",{parentName:"blockquote"},"(b) The contribution is based upon previous work that, to the best\nof my knowledge, is covered under an appropriate open source\nlicense and I have the right under that license to submit that\nwork with modifications, whether created in whole or in part\nby me, under the same open source license (unless I am\npermitted to submit under a different license), as indicated\nin the file; or"),(0,i.kt)("p",{parentName:"blockquote"},"(c) The contribution was provided directly to me by some other\nperson who certified (a), (b) or (c) and I have not modified\nit."),(0,i.kt)("p",{parentName:"blockquote"},"(d) I understand and agree that this project and the contribution\nare public and that a record of the contribution (including all\npersonal information I submit with it, including my sign-off) is\nmaintained indefinitely and may be redistributed consistent with\nthis project or the open source license(s) involved.")),(0,i.kt)("p",null,"Contributors ",(0,i.kt)("em",{parentName:"p"},"sign-off")," that they adhere to these requirements by adding a ",(0,i.kt)("inlineCode",{parentName:"p"},"Signed-off-by")," line to commit messages."),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-text"},"This is my commit message\n\nSigned-off-by: Random J Developer <random@developer.example.org>\n")),(0,i.kt)("p",null,"Git even has a ",(0,i.kt)("inlineCode",{parentName:"p"},"-s")," command line option to append this automatically to your commit message:"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-bash"},"git commit -s -m 'This is my commit message'\n")),(0,i.kt)("p",null,"Pull requests that do not contain a valid ",(0,i.kt)("inlineCode",{parentName:"p"},"Signed-off-by")," line cannot be merged."),(0,i.kt)("h3",{id:"i-didnt-sign-my-commit-now-what"},"I didn't sign my commit, now what?"),(0,i.kt)("p",null,"No worries - You can easily amend your commit with a sign-off and force push the change to your submitting branch:"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-bash"},"git switch <branch-name>\ngit commit --amend --no-edit --signoff\ngit push --force-with-lease <remote-name> <branch-name>\n")),(0,i.kt)("h2",{id:"code-of-conduct"},"Code of Conduct"),(0,i.kt)("p",null,"This project has adopted the ",(0,i.kt)("a",{parentName:"p",href:"/copacetic/website/v0.4.x/code-of-conduct"},"Contributor Covenant Code of Conduct"),"."))}p.isMDXComponent=!0}}]);