/*
 This is a copy-paste hijack that removes breakable invisible characters
 for a clean copy/paste experience.
 */


document.oncopy = alter_copy;

function alter_copy() {
    let body_element = document.getElementsByTagName('body')[0];
    let selection = window.getSelection();
    let sel_text = selection.toString().replace(/\u200b/gi, '');

    let newDiv = document.createElement('pre');
    newDiv.style.position = 'absolute';
    newDiv.style.left = '-99999px';

    body_element.appendChild(newDiv);
    newDiv.innerText = sel_text;
    selection.selectAllChildren(newDiv);
    window.setTimeout(function () {
        body_element.removeChild(newDiv);
    }, 0);
}
