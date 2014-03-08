var f = EventTarget.prototype.addEventListener;
EventTarget.prototype.addEventListener = function(type, fn, capture) {
    this.f = f;
    this.f(type, fn, capture);
    if(type != "submit")
        return;
    this.f(type, function(e){
        //code to add auth token to the ongoing request    
    }, capture);
}


//sample event listener 
function addListener() {
    var button = document.getElementById('submit');
    button.addEventListener('click', function() { alert('clicked222') }, false);
}