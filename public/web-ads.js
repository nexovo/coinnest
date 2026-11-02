'use strict';
// Manual, content-only placements. No auto ads or reward for web impressions/clicks.
(async()=>{
 try{
 const config=await fetch('/ads/web-config').then(r=>{if(!r.ok)throw Error('config');return r.json();});
 if(!config.enabled||!config.slots.some(Boolean))return;
 // Default off. The visitor can read the entire guide without loading Google ads.
 const choice=document.querySelector('#ad-choice');choice.hidden=false;
 document.querySelector('#allow-ads').addEventListener('click',()=>{
  choice.hidden=true;
  config.slots.forEach((slot,i)=>{
   if(!slot)return;const host=document.querySelector('[data-placement="'+i+'"]');
   host.hidden=false;
   const ad=document.createElement('ins');ad.className='adsbygoogle';ad.style.display='block';
   ad.dataset.adClient=config.client;ad.dataset.adSlot=slot;ad.dataset.adFormat='auto';ad.dataset.fullWidthResponsive='true';host.append(ad);
   (window.adsbygoogle=window.adsbygoogle||[]).push({});
  });
  const script=document.createElement('script');script.async=true;script.crossOrigin='anonymous';
  script.src='https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client='+config.client;
  document.head.append(script);
 },{once:true});
 document.querySelector('#decline-ads').addEventListener('click',()=>choice.hidden=true,{once:true});
 }catch(e){console.info('Web ads unavailable');}
})();
