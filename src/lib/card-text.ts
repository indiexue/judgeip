// Reserve room for the score tile without truncating the address itself.
export function ipFontSize(ip: string, width: number, preferred: number): number {
  return Math.min(preferred, Math.floor(width / (ip.length * 0.65)));
}

export function cardText(text: string, maxUnits: number): string {
  let units = 0;
  let result = '';
  for (const char of text) {
    units += /[^\x00-\x7f]/.test(char) ? 2 : 1;
    if (units > maxUnits) return result + '…';
    result += char;
  }
  return result;
}
