!function(e){function t(t){for(var n,s,d=t[0],i=t[1],c=t[2],u=0,f=[];u<d.length;u++)s=d[u],o[s]&&f.push(o[s][0]),o[s]=0;for(n in i)Object.prototype.hasOwnProperty.call(i,n)&&(e[n]=i[n]);for(l&&l(t);f.length;)f.shift()();return r.push.apply(r,c||[]),a()}function a(){for(var e,t=0;t<r.length;t++){for(var a=r[t],n=!0,d=1;d<a.length;d++){var i=a[d];0!==o[i]&&(n=!1)}n&&(r.splice(t--,1),e=s(s.s=a[0]))}return e}var n={},o={0:0},r=[];function s(t){if(n[t])return n[t].exports;var a=n[t]={i:t,l:!1,exports:{}};return e[t].call(a.exports,a,a.exports,s),a.l=!0,a.exports}s.m=e,s.c=n,s.d=function(e,t,a){s.o(e,t)||Object.defineProperty(e,t,{enumerable:!0,get:a})},s.r=function(e){"undefined"!=typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(e,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(e,"__esModule",{value:!0})},s.t=function(e,t){if(1&t&&(e=s(e)),8&t)return e;if(4&t&&"object"==typeof e&&e&&e.__esModule)return e;var a=Object.create(null);if(s.r(a),Object.defineProperty(a,"default",{enumerable:!0,value:e}),2&t&&"string"!=typeof e)for(var n in e)s.d(a,n,function(t){return e[t]}.bind(null,n));return a},s.n=function(e){var t=e&&e.__esModule?function(){return e.default}:function(){return e};return s.d(t,"a",t),t},s.o=function(e,t){return Object.prototype.hasOwnProperty.call(e,t)},s.p="";var d=window.webpackJsonp=window.webpackJsonp||[],i=d.push.bind(d);d.push=t,d=d.slice();for(var c=0;c<d.length;c++)t(d[c]);var l=i;r.push([7,1]),a()}([,function(e,t){e.exports=jQuery},function(e,t){e.exports=GravAdmin},,,function(e,t,a){"use strict";Object.defineProperty(t,"__esModule",{value:!0});var n,o=a(13),r=(n=o)&&n.__esModule?n:{default:n};r.default.options.positionClass="toast-top-right",r.default.options.preventDuplicates=!0,t.default=r.default},function(e,t,a){"use strict";(function(e){Object.defineProperty(t,"__esModule",{value:!0});var n=r(a(1)),o=r(a(6));function r(e){return e&&e.__esModule?e:{default:e}}var s=(0,n.default)("#offline-status");(0,n.default)(window).on("offline",function(){s.slideDown()}),(0,n.default)(window).on("online",function(){s.slideUp()}),(0,n.default)(document).ready(function(){o.default||s.slideDown()}),t.default=void 0===e.navigator.onLine||e.navigator.onLine}).call(this,a(0))},function(e,t,a){"use strict";a(8)},function(e,t,a){"use strict";(function(e){Object.defineProperty(t,"__esModule",{value:!0});var n=i(a(9)),o=i(a(10)),r=i(a(5)),s=a(2),d=i(a(1));function i(e){return e&&e.__esModule?e:{default:e}}var c=(0,d.default)('[data-remodal-id="wizard"]'),l=(0,d.default)('[data-remodal-id="reset-local"]'),u={github:"github.com",bitbucket:"bitbucket.org",gitlab:"gitlab.com",allothers:"allothers.repo"},f={REPO_URL:"https://{placeholder}/getgrav/grav.git"},p=function(){var e=c.remodal({closeOnConfirm:!1}),t=c.find('[data-gitsync-action="previous"]'),a=c.find('[data-gitsync-action="next"]'),n=c.find('[data-gitsync-action="save"]');m=0,c.find("form > [class^=step-]:not(.step-"+m+") > .panel").hide().removeClass("hidden"),c.find('form > [class="step-'+m+'"] > .panel').show(),a.removeClass("hidden"),t.addClass("hidden"),n.addClass("hidden");var o=(0,d.default)('[name="data[webhook]"]').val(),r=(0,d.default)('[name="data[webhook_secret]"]').val();(0,d.default)('[name="gitsync[repository]"]').trigger("change"),(0,d.default)('[name="gitsync[webhook]"]').val(o),(0,d.default)('[name="gitsync[webhook_secret]"]').val(r),(0,d.default)(".gitsync-webhook").text(o),e.open()},h=function(e){e.attr("disabled","disabled").addClass("hint--top")},v=function(e){e.attr("disabled",null).removeClass("hint--top")},m=0,g=0,b=null;(0,d.default)(document).on("closed",c,function(e){m=0}),(0,d.default)(document).on("click","[data-gitsync-useraction]",function(e){e.preventDefault();var t=(0,d.default)(e.target).closest("[data-gitsync-useraction]"),a=t.data("gitsyncUseraction"),n=s.config.current_url+".json";switch(a){case"wizard":p();break;case"sync":var r=t.data("gitsync-uri");t.find("i").removeClass("fa-cloud fa-git").addClass("fa-circle-o-notch fa-spin"),(0,o.default)(r||n,{method:"post",body:{task:"synchronize"}},function(){t.find("i").removeClass("fa-circle-o-notch fa-spin").addClass(r?"fa-git":"fa-cloud")});break;case"reset":var i=l.remodal({closeOnConfirm:!1});i.open(),l.data("_reset_event_set_")||l.find('[data-gitsync-action="reset-local"]').one("click",function(){i.close(),l.data("_reset_event_set_",!0),t.find("i").removeClass("fa-history").addClass("fa-circle-o-notch fa-spin"),(0,o.default)(n,{method:"post",body:{task:"resetlocal"}},function(){l.data("_reset_event_set_",!1),t.find("i").removeClass("fa-circle-o-notch fa-spin").addClass("fa-history")})})}}),(0,d.default)(document).on("click","[data-gitsync-action]",function(t){t.preventDefault();var a=(0,d.default)(t.target).closest("[data-gitsync-action]"),n=c.find('[data-gitsync-action="previous"]'),i=c.find('[data-gitsync-action="next"]'),l=c.find('[data-gitsync-action="save"]'),u=a.data("gitsyncAction"),f=(0,d.default)('[name="gitsync[repo_user]"]').val(),p=(0,d.default)('[name="gitsync[repo_password]"]').val(),b=(0,d.default)('[name="gitsync[repo_url]"]').val(),y=(0,d.default)('[name="gitsync[webhook]"]').val(),k=(0,d.default)('[name="gitsync[webhook_enabled]"]').is(":checked"),_=(0,d.default)('[name="gitsync[webhook_secret]"]').val();if(!a.attr("disabled")){var w=[];if(f||w.push("Username is missing."),b||w.push("Repository is missing."),["save","test"].includes(u)&&w.length)return r.default.error(w.join("<br />")),!1;if("save"===u){var C=(0,d.default)('[name="gitsync[folders]"]:checked').map(function(e,t){return t.value});(0,d.default)('[name="data[repository]"]').val(b),(0,d.default)('[name="data[user]"]').val(f),(0,d.default)('[name="data[password]"]').val(p),(0,d.default)('[name="data[webhook]"]').val(y),(0,d.default)('[name="data[webhook_enabled]"][value="'+(k?1:0)+'"]').prop("checked",!0),(0,d.default)('[name="data[webhook_secret]"]').val(_);var O=(0,d.default)('[name="data[folders][]"]');return O&&O[0]&&O[0].selectize&&O[0].selectize.setValue(C.toArray()),(0,d.default)('[name="task"][value="save"]').trigger("click"),!1}if("test"===u){var j=s.config.current_url+".json",x=e.btoa(JSON.stringify({user:f,password:p,repository:b}));return(0,o.default)(j,{method:"post",body:{test:x,task:"testConnection"}}),!1}if(c.find(".step-"+m+" > .panel").slideUp(),m+="next"===u?1:-1,c.find(".step-"+m+" > .panel").slideDown(),l.addClass("hidden"),"next"===u&&n.removeClass("hidden"),m<=0&&n.addClass("hidden"),m>0&&i.removeClass("hidden"),1===m)(0,d.default)('[name="gitsync[repository]"]:checked').length?v(i):h(i);if(2===m)(0,d.default)('[name="gitsync[repo_url]"]').val().length?v(i):h(i);m===g&&(i.addClass("hidden"),n.removeClass("hidden"),l.removeClass("hidden"))}}),(0,d.default)(document).on("change",'[name="gitsync[repository]"]',function(){v(c.find('[data-gitsync-action="next"]'))}),(0,d.default)(document).on("input",'[name="gitsync[repo_url]"]',function(e){var t=(0,d.default)(e.currentTarget).val(),a=c.find('[data-gitsync-action="next"]');t.length?v(a):h(a)}),(0,d.default)(document).on("keyup",'[data-gitsync-uribase] [name="gitsync[webhook]"]',function(e){var t=(0,d.default)(e.currentTarget).val();(0,d.default)(".gitsync-webhook").text(t)}),(0,d.default)(document).on("keyup",'[data-gitsync-uribase] [name="gitsync[webhook_secret]"]',function(e){(0,d.default)('[data-gitsync-uribase] [name="gitsync[webhook_enabled]"]').trigger("change")}),(0,d.default)(document).on("change",'[data-gitsync-uribase] [name="gitsync[webhook_enabled]"]',function(e){var t=(0,d.default)(e.currentTarget),a=t.is(":checked"),n=(0,d.default)('[name="gitsync[webhook_secret]"]').val();t.closest(".webhook-secret-wrapper").find("label:last-child")[a?"removeClass":"addClass"]("hidden"),(0,d.default)(".gitsync-webhook-secret").html(a&&n.length?"<code>"+n+"</code>":"<em>leave empty</em>")}),(0,d.default)(document).on("change",'[name="gitsync[repository]"]',function(e){var t=(0,d.default)(e.target);t.is(":checked")&&(b=t.val(),Object.keys(u).forEach(function(e){c.find(".hidden-step-"+e)[e===b?"removeClass":"addClass"]("hidden"),e===b&&(c.find(".webhook-secret-wrapper")["bitbucket"===e?"addClass":"removeClass"]("hidden"),c.find('input[name="gitsync[repo_url]"][placeholder]').attr("placeholder",f.REPO_URL.replace(/\{placeholder\}/,u[e])))}))}),(0,d.default)(document).on("click","[data-access-tokens-details]",function(e){e.preventDefault();var t=(0,d.default)(e.currentTarget),a=t.closest(".access-tokens").find(".access-tokens-details");a.slideToggle(250,function(){var e=a.is(":visible");t.find(".fa").removeClass("fa-chevron-down fa-chevron-up").addClass("fa-chevron-"+(e?"up":"down"))})});var y=function(e){var t=(0,d.default)(e),a=t.val(),n=t.closest(".columns").find(".column:last");n.find('[class*="description-"]').addClass("hidden"),n.find(".description-"+a).removeClass("hidden").hide().fadeIn({duration:250})};(0,d.default)(document).on("input",'[data-remodal-id="wizard"] .step-4 input[type="checkbox"]',function(e){var t=(0,d.default)(e.currentTarget);t.is(":checked")&&y(t)}),(0,d.default)(document).on("mouseenter",'[data-remodal-id="wizard"] .step-4 .info-desc',function(e){var t=(0,d.default)(e.currentTarget).siblings('input[type="checkbox"]');y(t)}),(0,d.default)(document).on("mouseleave",'[data-remodal-id="wizard"] .step-4 label',function(e){(0,d.default)(e.currentTarget).closest(".columns").find(".column:last-child").find('[class*="description-"]').addClass("hidden")}),(0,d.default)(document).on("mouseleave",'[data-remodal-id="wizard"] .columns .column:first-child',function(e){(0,d.default)(e.currentTarget).siblings(".column").find('[class*="description-"]').addClass("hidden")}),(0,d.default)(document).ready(function(){g=c.find('[class^="step-"]').length-1,c.wrapInner("<form></form>"),l.wrapInner("<form></form>"),!c.length||!n.default.first_time&&n.default.git_installed||p()}),t.default=n.default}).call(this,a(0))},function(e,t){e.exports=GitSync},function(e,t,a){"use strict";(function(e){Object.defineProperty(t,"__esModule",{value:!0});var n=a(12),o=a(2),r=void 0;t.default=function(t){var a=arguments.length>1&&void 0!==arguments[1]?arguments[1]:{},s=arguments.length>2&&void 0!==arguments[2]?arguments[2]:function(){return!0};if("function"==typeof a&&(s=a,a={}),a.method&&"post"===a.method){var d=new FormData;a.body=Object.assign({"admin-nonce":o.config.admin_nonce},a.body||{}),Object.keys(a.body).map(function(e){return d.append(e,a.body[e])}),a.body=d}return a=Object.assign({credentials:"same-origin",headers:{Accept:"application/json"}},a),e(t,a).then(function(e){return r=e,e}).then(n.parseStatus).then(n.parseJSON).then(n.userFeedback).then(function(e){return s(e,r)}).catch(n.userFeedbackError)}}).call(this,a(11))},,function(e,t,a){"use strict";(function(e){Object.defineProperty(t,"__esModule",{value:!0}),t.parseStatus=function(e){return e},t.parseJSON=function(e){return e.text().then(function(e){var t=e;try{t=JSON.parse(e)}catch(t){var a=document.createElement("div");a.innerHTML=e;var n=new Error;throw n.stack=(0,d.default)(a.innerText),n}return t})},t.userFeedback=function(e){if(c)return!0;var t=e.status||(e.error?"error":""),a=e.message||(e.error?e.error.message:null),n=e.toastr||null,d=void 0;switch(t){case"unauthenticated":throw document.location.href=s.config.base_url_relative,l("Logged out");case"unauthorized":t="error",a=a||"Unauthorized.";break;case"error":t="error",a=a||"Unknown error.";break;case"success":t="success",a=a||"";break;default:t="error",a=a||"Invalid AJAX response."}n&&(d=Object.assign({},o.default.options),Object.keys(n).forEach(function(e){o.default.options[e]=n[e]}));a&&(r.default||!r.default&&"error"!==t)&&o.default["success"===t?"success":"error"](a);n&&(o.default.options=d);return e},t.userFeedbackError=function(e){if(c)return!0;var t=e.stack?"<pre><code>"+e.stack+"</code></pre>":"";o.default.error("Fetch Failed: <br /> "+e.message+" "+t)};var n=i(a(1)),o=i(a(5)),r=i(a(6)),s=a(2),d=i(a(15));function i(e){return e&&e.__esModule?e:{default:e}}var c=!1,l=function(e){var t=new Error(e.statusText||e||"");return t.response=e,t};(0,n.default)(e).on("beforeunload._ajax",function(){c=!0})}).call(this,a(0))}]);