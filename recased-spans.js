// Which spans the RE-CASED detection pass may add (pii-detect.js recaseForDetection).
//
// People type chat in lowercase, and cased NER models miss a lowercase name, so the gateway runs
// its detector a second time over a copy with every uncommon word capitalised and unions the
// spans. On lowercase text that second pass is where every hit comes from — measured 2026-09-30
// on the bundled detectors, the original-case pass found nothing in twelve lowercase questions.
// It finds the right things (`jordan blake`, `seattle`, `allstate`, `acme robotics`) — and, on a
// short query, the copy reads like a headline: "Best Home Insurance Quotes in 98065 for 1M
// Dwelling" came back as an ORGANISATION ("best home insurance") and an ADDRESS ("1m
// dwelling"). The model was sent `[[ORG_1]] quotes in [[ADDRESS_2]] for [[ADDRESS_1]]` and told
// the person their insurer's name had not come through — they had named no insurer.
//
// The false spans share a shape, so the rule is about the shape, not about phrases:
//   • an ORGANISATION the re-cased pass alone found must hold a word that is not ordinary
//     English. "best home insurance", "cheap car insurance", "compare state farm" are made of
//     dictionary words that were capitalised only because the copy capitalises them; "allstate",
//     "acme robotics", "microsoft stock" each hold a word that is not. A company named only in
//     ordinary words AND typed in lowercase ("state farm") is not redacted by this pass; typed as
//     it is written ("State Farm") the original pass still finds it, and a name the person must
//     never send belongs in their redaction dictionary, which is matched exactly.
//   • an ADDRESS the re-cased pass alone found must hold a house number standing on its own:
//     "1200 se maple st" yes, "1M dwelling" (a quantity) no.
//   • PEOPLE and PLACES are untouched — they are what the pass exists for, and dropping a
//     lowercase name or city would be a leak.
// A span the original pass found is never judged here.

import { normType } from './pii-detect.js';

// Ordinary English words: the ~900 most frequent, plus the everyday nouns and adjectives of the
// questions people ask an assistant (shopping, money, travel, home). Lowercase, singular.
const ORDINARY = new Set((
  'a about above across act action add address after again against age ago agree air all allow almost alone along already also although always am among amount an and animal annual another answer any anyone anything apartment app appear apply area arm around arrive art article as ask at attack audience author available average avoid away baby back bad bag balance ball bank bar base basic bath be beach bear beat beautiful because become bed been before begin behavior behind being believe below benefit best better between big bike bill bit black blood blue board boat body book born both box boy break breakfast bring brother brown budget build building business but buy by call camera campaign can cancer candidate capital car card care career carry case cash cat catch cause cell center central century certain chair challenge chance change channel charge cheap check child choice choose church citizen city civil claim class clean clear close coach coast coat code coffee cold collection college color come commercial common community company compare computer concern condition conference consider consumer contain continue contract control cook cool corner cost could country county couple course court cover coverage create credit crime cultural culture cup current customer cut daily damage dark data date daughter day dead deal death debt decade decide decision deep deductible defense degree deliver delivery department depend describe design despite detail determine develop development device die diet difference different difficult dinner direct direction discount discover discuss disease do doctor dog door down draw dream dress drink drive driver drop drug during each early earn east easy eat economic economy edge education effect effort eight either election electric else employee end energy enjoy enough enter entire environment equal estate even evening event ever every evidence exactly example exchange exercise exist expect expense expensive experience expert explain eye face fact factor fail fall family far farm fast father fear federal fee feel few field fight figure file fill film final finally finance financial find fine finger finish fire firm first fish fit five fix flat flight floor flower fly focus follow food foot for force foreign forget form former forward four free fresh friend from front fruit full fun fund future game garage garden gas general generation get gift girl give glass go goal good government great green ground group grow growth guess gun guy hair half hand hang happen happy hard have he head health hear heart heat heavy help her here herself high him himself his history hit hold holiday home hope hospital hot hotel hour house household how however huge human hundred husband idea identify if image imagine impact important improve in include including income increase indeed indicate individual industry information inside instead institution insurance interest interesting international interview into invest investment involve issue it item its itself job join just keep key kid kill kind kitchen know knowledge land language large last late later laugh law lawyer lay lead leader learn least leave left leg legal less let letter level life light like likely line list listen little live loan local long look lose loss lot love low lunch machine magazine main maintain major majority make man manage management manager many market marriage material matter may maybe me mean measure media medical meet meeting member memory mention message method middle might military million mind minute miss mission model modern moment money month monthly more morning mortgage most mother mouth move movie much music must my myself name nation national natural nature near nearly necessary need network never new news newspaper next nice night no none nor north not note nothing notice now number occur of off offer office officer official often oil ok old on once one only onto open operation opportunity option or order organization other others our out outside over own owner page pain paint paper parent park part participant particular partner party pass past patient pattern pay payment peace people per percent perform performance perhaps period person personal phone physical pick picture piece place plan plant play player plus point police policy political poor popular population position positive possible power practice premium prepare present president pressure pretty prevent price private probably problem process produce product production professional program project property protect protection prove provide public pull purpose push put quality question quick quickly quiet quite quote race radio raise range rate rather reach read ready real reality realize really reason receive recent recently recognize record red reduce reflect region relate relationship religious remain remember remove rent repair report represent require research resource respond response rest restaurant result return reveal review reward rich ride right rise risk river road rock role roof room rule run safe safety sale same save say scene school science score sea season seat second section security see seek seem sell send senior sense series serious serve service set seven several shake share she shoe shop shopping short shot should shoulder show side sign significant similar simple simply since sing single sister sit site situation six size skill skin small smile so social society soft soldier some somebody someone something sometimes son song soon sort sound source south space speak special specific speech spend sport spring staff stage stand standard star start state statement station stay step still stock stop store story strategy street strong structure student study stuff style subject success successful such suddenly suffer suggest summer support sure surface system table take talk task tax teach teacher team technology television tell ten tend term test than thank that the their them themselves then theory there these they thing think third this those though thought thousand threat three through throughout throw thus ticket time tire to today together tonight too top total tough toward town trade traditional train training travel treat treatment tree trial trip trouble true truth try turn tv two type under understand unit until up upon us use usually value various very victim view village violence visit voice vote wait walk wall want war warm warranty wash watch water way we weapon wear weather week weight well west western what whatever when where whether which while white who whole whom whose why wide wife will win wind window winter wish with within without woman wonder word work worker world worry worth would write writer wrong yard yeah year yes yet you young your yourself'
).split(/\s+/));

// The singular of a plural the list holds: "quotes" → "quote", "policies" → "policy".
const ordinary = (w) => {
  const s = w.toLowerCase().replace(/[’']s$/, '');
  if (ORDINARY.has(s)) return true;
  if (s.endsWith('ies') && ORDINARY.has(`${s.slice(0, -3)}y`)) return true;
  if (s.endsWith('es') && ORDINARY.has(s.slice(0, -2))) return true;
  return s.endsWith('s') && ORDINARY.has(s.slice(0, -1));
};

/** Is every word of `text` ordinary English (digits and punctuation aside)? */
export function allOrdinary(text) {
  const words = String(text || '').match(/\p{L}[\p{L}’'-]*/gu) || [];
  return words.length > 0 && words.every(ordinary);
}

/**
 * May the RE-CASED pass add this span? `label` is the detector's own (normalised with
 * pii-detect.js normType). True for people and places; for an organisation, only when it holds
 * a word that is not ordinary English; for an address, only with a house number of its own.
 */
export function recasedSpanOk(value, label) {
  const type = normType(label);
  if (type === 'ORG') return !allOrdinary(value);
  if (type === 'ADDRESS') return /(?:^|\s)\d{1,6}(?=\s|$)/.test(String(value || '').trim());
  return true;
}
