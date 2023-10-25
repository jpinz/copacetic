"use strict";(self.webpackChunkwebsite=self.webpackChunkwebsite||[]).push([[6148],{3905:(e,t,a)=>{a.d(t,{Zo:()=>s,kt:()=>h});var n=a(7294);function i(e,t,a){return t in e?Object.defineProperty(e,t,{value:a,enumerable:!0,configurable:!0,writable:!0}):e[t]=a,e}function o(e,t){var a=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),a.push.apply(a,n)}return a}function r(e){for(var t=1;t<arguments.length;t++){var a=null!=arguments[t]?arguments[t]:{};t%2?o(Object(a),!0).forEach((function(t){i(e,t,a[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(a)):o(Object(a)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(a,t))}))}return e}function l(e,t){if(null==e)return{};var a,n,i=function(e,t){if(null==e)return{};var a,n,i={},o=Object.keys(e);for(n=0;n<o.length;n++)a=o[n],t.indexOf(a)>=0||(i[a]=e[a]);return i}(e,t);if(Object.getOwnPropertySymbols){var o=Object.getOwnPropertySymbols(e);for(n=0;n<o.length;n++)a=o[n],t.indexOf(a)>=0||Object.prototype.propertyIsEnumerable.call(e,a)&&(i[a]=e[a])}return i}var c=n.createContext({}),p=function(e){var t=n.useContext(c),a=t;return e&&(a="function"==typeof e?e(t):r(r({},t),e)),a},s=function(e){var t=p(e.components);return n.createElement(c.Provider,{value:t},e.children)},u="mdxType",d={inlineCode:"code",wrapper:function(e){var t=e.children;return n.createElement(n.Fragment,{},t)}},m=n.forwardRef((function(e,t){var a=e.components,i=e.mdxType,o=e.originalType,c=e.parentName,s=l(e,["components","mdxType","originalType","parentName"]),u=p(a),m=i,h=u["".concat(c,".").concat(m)]||u[m]||d[m]||o;return a?n.createElement(h,r(r({ref:t},s),{},{components:a})):n.createElement(h,r({ref:t},s))}));function h(e,t){var a=arguments,i=t&&t.mdxType;if("string"==typeof e||i){var o=a.length,r=new Array(o);r[0]=m;var l={};for(var c in t)hasOwnProperty.call(t,c)&&(l[c]=t[c]);l.originalType=e,l[u]="string"==typeof e?e:i,r[1]=l;for(var p=2;p<o;p++)r[p]=a[p];return n.createElement.apply(null,r)}return n.createElement.apply(null,a)}m.displayName="MDXCreateElement"},9974:(e,t,a)=>{a.r(t),a.d(t,{assets:()=>c,contentTitle:()=>r,default:()=>u,frontMatter:()=>o,metadata:()=>l,toc:()=>p});var n=a(7462),i=(a(7294),a(3905));const o={title:"FAQ"},r=void 0,l={unversionedId:"faq",id:"version-v0.5.x/faq",title:"FAQ",description:"What kind of vulnerabilities can Copa patch?",source:"@site/versioned_docs/version-v0.5.x/faq.md",sourceDirName:".",slug:"/faq",permalink:"/copacetic/website/faq",draft:!1,tags:[],version:"v0.5.x",frontMatter:{title:"FAQ"},sidebar:"sidebar",previous:{title:"Design",permalink:"/copacetic/website/design"},next:{title:"Scanner Plugins",permalink:"/copacetic/website/scanner-plugins"}},c={},p=[{value:"What kind of vulnerabilities can Copa patch?",id:"what-kind-of-vulnerabilities-can-copa-patch",level:2},{value:"What kind of vulnerabilities can Copa not patch?",id:"what-kind-of-vulnerabilities-can-copa-not-patch",level:2},{value:"Can I replace the package repositories in the image with my own?",id:"can-i-replace-the-package-repositories-in-the-image-with-my-own",level:2}],s={toc:p};function u(e){let{components:t,...a}=e;return(0,i.kt)("wrapper",(0,n.Z)({},s,a,{components:t,mdxType:"MDXLayout"}),(0,i.kt)("h2",{id:"what-kind-of-vulnerabilities-can-copa-patch"},"What kind of vulnerabilities can Copa patch?"),(0,i.kt)("p",null,'Copa is capable of patching "OS level" vulnerabilities. This includes packages (like ',(0,i.kt)("inlineCode",{parentName:"p"},"openssl"),") in the image that are managed by a package manager such as ",(0,i.kt)("inlineCode",{parentName:"p"},"apt")," or ",(0,i.kt)("inlineCode",{parentName:"p"},"yum"),'. Copa is not currently capable of patching vulnerabilities at the "application level" such as Python packages or Go modules (see ',(0,i.kt)("a",{parentName:"p",href:"#what-kind-of-vulnerabilities-can-copa-not-patch"},"below")," for more details)."),(0,i.kt)("h2",{id:"what-kind-of-vulnerabilities-can-copa-not-patch"},"What kind of vulnerabilities can Copa not patch?"),(0,i.kt)("p",null,'Copa is not capable of patching vulnerabilities for compiled languages, like Go, at the "application level", for instance, Go modules. If your application uses a vulnerable version of the ',(0,i.kt)("inlineCode",{parentName:"p"},"golang.org/x/net")," module, Copa will be unable to patch it. This is because Copa doesn't have access to the application's source code or the knowledge of how to build it, such as compiler flags, preventing it from patching vulnerabilities at the application level."),(0,i.kt)("p",null,"To patch vulnerabilities for applications, you can package these applications and consume them from package repositories, like ",(0,i.kt)("inlineCode",{parentName:"p"},"http://archive.ubuntu.com/ubuntu/")," for Ubuntu, and ensure Trivy can scan and report vulnerabilities for these packages. This way, Copa can patch the applications as a whole, though it cannot patch specific modules within the applications."),(0,i.kt)("h2",{id:"can-i-replace-the-package-repositories-in-the-image-with-my-own"},"Can I replace the package repositories in the image with my own?"),(0,i.kt)("admonition",{type:"caution"},(0,i.kt)("p",{parentName:"admonition"},"Experimental: This feature might change without preserving backwards compatibility.")),(0,i.kt)("p",null,"Copa does not support replacing the repositories in the package managers with alternatives. Images must already use the intended package repositories. For example, for debian, updating ",(0,i.kt)("inlineCode",{parentName:"p"},"/etc/apt/sources.list")," from ",(0,i.kt)("inlineCode",{parentName:"p"},"http://archive.ubuntu.com/ubuntu/")," to a mirror, such as ",(0,i.kt)("inlineCode",{parentName:"p"},"https://mirrors.wikimedia.org/ubuntu/"),"."),(0,i.kt)("p",null,"If you need the tooling image to use a different package repository, you can create a source policy to define a replacement image and/or pin to a digest. For example, the following source policy replaces ",(0,i.kt)("inlineCode",{parentName:"p"},"docker.io/library/debian:11-slim")," image with ",(0,i.kt)("inlineCode",{parentName:"p"},"foo.io/bar/baz:latest@sha256:42d3e6bc186572245aded5a0be381012adba6d89355fa9486dd81b0c634695b5"),":"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-shell"},'cat <<EOF > source-policy.json\n{\n    "rules": [\n        {\n            "action": "CONVERT",\n            "selector": {\n                "identifier": "docker-image://docker.io/library/debian:11-slim"\n            },\n            "updates": {\n                "identifier": "docker-image://foo.io/bar/baz:latest@sha256:42d3e6bc186572245aded5a0be381012adba6d89355fa9486dd81b0c634695b5"\n            }\n        }\n    ]\n}\nEOF\n\nexport EXPERIMENTAL_BUILDKIT_SOURCE_POLICY=source-policy.json\n')),(0,i.kt)("blockquote",null,(0,i.kt)("p",{parentName:"blockquote"},"Tooling image for Debian-based images are ",(0,i.kt)("inlineCode",{parentName:"p"},"docker.io/library/debian:11-slim")," and RPM-based repos are ",(0,i.kt)("inlineCode",{parentName:"p"},"mcr.microsoft.com/cbl-mariner/base/core:2.0"),".")),(0,i.kt)("p",null,"For more information on source policies, see ",(0,i.kt)("a",{parentName:"p",href:"https://docs.docker.com/build/building/env-vars/#experimental_buildkit_source_policy"},"Buildkit Source Policies"),"."))}u.isMDXComponent=!0}}]);