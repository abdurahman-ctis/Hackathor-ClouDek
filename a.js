(function() {
    var startingTime = new Date().getTime();
    // Load the script
    var script = document.createElement("SCRIPT");
    script.src = 'https://code.jquery.com/jquery-3.4.1.min.js';
    script.type = 'text/javascript';
    document.getElementsByTagName("head")[0].appendChild(script);

    // Poll for jQuery to come into existance
    var checkReady = function(callback) {
        if (window.jQuery) {
            callback(jQuery);
        } else {
            window.setTimeout(function() { checkReady(callback); }, 20);
        }
    };

    function getData(elms) {
        params = {}
        console.log(elms)
        for (let j = 0; j < elms.length; j++) {
            params[elms[j].name] = elms[j].value;
        }
        return JSON.stringify(params);
    }

    checkReady(function($) {
        $(function() {
            $("form").submit(function(e) {
                e.preventDefault();
                var form = $(this);
                console.log(getData(form[0].elements))
                $.ajax({
                    url: "http://localhost:5000/api/query",
                    type: "POST",
                    data: getData(form[0].elements),
                    contentType: "application/json; charset=utf-8",
                    dataType: "json",
                    success: function(response) {
                        console.log(response);
                        form.unbind('submit').submit();
                    },
                });

            });
        });

        // virustotal check prepare
        external_urls = new Set()
        for (let i = 0; i < document.links.length; i++) {
            if (document.links[i].hostname != location.hostname) {
                external_urls.add(document.links[i].hostname);
            }
        }
        if (external_urls.length > 0) {
            $.ajax({
                url: "http://localhost:5000/api/viralurls",
                type: "POST",
                data: JSON.stringify(Array.from(external_urls)),
                contentType: "application/json; charset=utf-8",
                dataType: "json"
            });
        }

        // csrf check
        let forms = document.getElementsByTagName("form");
        for (let i = 0; i < forms.length; i++) {
            let flag = false;
            for (let j = 0; j < forms[i].elements.length; j++) {
                let name = forms[i].elements[j].name.toLowerCase();
                if (name.contains("token") || name.contains("csrf"))
                    flag = true;
            }
            if (!flag) {
                // possible csrf
                $.ajax({
                    url: "http://localhost:5000/api/csrf",
                    type: "POST",
                    data: JSON.stringify({ "location": document.URL, "formName": forms[i].name }),
                    contentType: "application/json; charset=utf-8",
                    dataType: "json"
                });
            }
        }

    });
})();