// Simple matrix background + small cursor-typing helper
(function(){
  // app/static/js/hacker.js
  const canvas = document.getElementById('matrix-canvas');
  if (canvas) {
    const ctx = canvas.getContext('2d');

    function fitCanvas() {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
    }
    fitCanvas();
    window.addEventListener('resize', fitCanvas);

    const letters = "アカサタナハマヤラワ010101010101010010101010170MR.ROBOT7ESCAPETHEMATRIXPLEASE";
    const fontSize = 14;
    const columns = Math.floor(window.innerWidth / fontSize);
    const ypos = Array(columns).fill(1);

    function matrixLoop(){
      // Blur / fade effect here
      ctx.fillStyle = "rgba(0, 0, 0, 0.07)";
      ctx.fillRect(0,0,canvas.width,canvas.height);

      ctx.fillStyle = "#0F0";
      ctx.font = fontSize + "px monospace";

      for (let i=0; i<ypos.length; i++){
        const text = letters[Math.floor(Math.random() * letters.length)];
        const x = i * fontSize;
        ctx.fillText(text, x, ypos[i] * fontSize);

        if (ypos[i] * fontSize > canvas.height && Math.random() > 0.975) {
          ypos[i] = 0;
        }
        ypos[i]++;
      }
    }
    setInterval(matrixLoop, 60);
  }

  // Typewriter effect
  document.addEventListener("DOMContentLoaded", function(){
    const nodes = document.querySelectorAll("[data-type]");
    nodes.forEach(node=>{
      const text = node.getAttribute("data-type");
      node.textContent = "";
      let i = 0;

      function typeChar(){
        if (i < text.length) {
          node.textContent += text[i++];
          setTimeout(typeChar, 25 + Math.random()*40);
        }
      }
      setTimeout(typeChar, 200);
    });
  });

})();
