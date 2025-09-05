const display = document.getElementById('display');
const buttons = document.querySelectorAll('.keys button');
let current = '';
buttons.forEach(btn => {
  btn.addEventListener('click', () => {
    const val = btn.value;
    if (val === '=') {
      try {
        // dangerous eval usage—SAST flag
        current = eval(current).toString();
      } catch {
        current = 'Error';
      }
    } else if (btn.id === 'clear') {
      current = '';
    } else {
      current += val;
    }
    display.value = current;
  });
});
