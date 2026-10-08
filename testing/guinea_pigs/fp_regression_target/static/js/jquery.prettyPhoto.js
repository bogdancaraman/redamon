(function($){
  $.prettyPhoto = function(){
    var hashIndex = location.hash.replace("#!", "");
    document.getElementById("pp_full_res").innerHTML = hashIndex;
  };
})(window.jQuery || {});
