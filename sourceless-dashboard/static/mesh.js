(function () {
  const canvas = document.getElementById('sl-mesh');
  if (canvas) {
    const reduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (reduced) {
      canvas.style.display = 'none';
    } else {
      const ctx = canvas.getContext('2d');
      let w = 0;
      let h = 0;
      let raf = 0;
      const pointer = { x: -9999, y: -9999 };
      const nodes = [];
      const NODE_COUNT = 44;

      function resize() {
        const dpr = Math.min(window.devicePixelRatio || 1, 1.5);
        w = window.innerWidth;
        h = window.innerHeight;
        canvas.width = Math.floor(w * dpr);
        canvas.height = Math.floor(h * dpr);
        canvas.style.width = w + 'px';
        canvas.style.height = h + 'px';
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      }

      function seed() {
        nodes.length = 0;
        for (let i = 0; i < NODE_COUNT; i++) {
          nodes.push({
            x: Math.random() * w,
            y: Math.random() * h,
            vx: (Math.random() - 0.5) * 0.32,
            vy: (Math.random() - 0.5) * 0.32,
            r: 1.3 + Math.random() * 1.4,
            lime: i % 5 === 0
          });
        }
      }

      function frame() {
        ctx.clearRect(0, 0, w, h);
        for (let i = 0; i < nodes.length; i++) {
          const a = nodes[i];
          a.x += a.vx;
          a.y += a.vy;
          if (a.x < 0 || a.x > w) a.vx *= -1;
          if (a.y < 0 || a.y > h) a.vy *= -1;

          const dxp = pointer.x - a.x;
          const dyp = pointer.y - a.y;
          const dp = Math.hypot(dxp, dyp);
          if (dp < 160 && dp > 1) {
            a.x -= (dxp / dp) * 0.18;
            a.y -= (dyp / dp) * 0.18;
          }

          for (let j = i + 1; j < nodes.length; j++) {
            const b = nodes[j];
            const d = Math.hypot(a.x - b.x, a.y - b.y);
            if (d < 145) {
              const alpha = (1 - d / 145) * 0.16;
              ctx.strokeStyle = (a.lime || b.lime)
                ? `rgba(167, 255, 82, ${alpha.toFixed(3)})`
                : `rgba(96, 84, 242, ${(alpha * 1.35).toFixed(3)})`;
              ctx.lineWidth = 1;
              ctx.beginPath();
              ctx.moveTo(a.x, a.y);
              ctx.lineTo(b.x, b.y);
              ctx.stroke();
            }
          }

          if (dp < 185) {
            const alpha = (1 - dp / 185) * 0.28;
            ctx.strokeStyle = `rgba(167, 255, 82, ${alpha.toFixed(3)})`;
            ctx.lineWidth = 1;
            ctx.beginPath();
            ctx.moveTo(a.x, a.y);
            ctx.lineTo(pointer.x, pointer.y);
            ctx.stroke();
          }

          ctx.fillStyle = a.lime ? 'rgba(167, 255, 82, 0.55)' : 'rgba(148, 155, 192, 0.42)';
          ctx.beginPath();
          ctx.arc(a.x, a.y, a.r, 0, Math.PI * 2);
          ctx.fill();
        }
        raf = requestAnimationFrame(frame);
      }

      window.addEventListener('resize', resize);
      window.addEventListener('pointermove', (e) => { pointer.x = e.clientX; pointer.y = e.clientY; }, { passive: true });
      document.addEventListener('visibilitychange', () => {
        if (document.hidden) {
          cancelAnimationFrame(raf);
        } else {
          cancelAnimationFrame(raf);
          raf = requestAnimationFrame(frame);
        }
      });

      resize();
      seed();
      raf = requestAnimationFrame(frame);
    }
  }

  document.querySelectorAll('.kpi-card, #loginCard').forEach((card) => {
    card.addEventListener('pointermove', (e) => {
      const r = card.getBoundingClientRect();
      card.style.setProperty('--mx', (e.clientX - r.left) + 'px');
      card.style.setProperty('--my', (e.clientY - r.top) + 'px');
    }, { passive: true });
  });
})();
