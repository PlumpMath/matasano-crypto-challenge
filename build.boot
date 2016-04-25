(def project 'matasano-crypto)
(def version "0.1.0-SNAPSHOT")

(set-env! :resource-paths #{"resources" "src"}
          :source-paths #{"test"}
          :dependencies '[[org.clojure/clojure "1.8.0"]
                          [adzerk/boot-test "1.1.1" :scope "test"]
                          [commons-codec/commons-codec "1.10"]])

(task-options!
 pom {:project     project
      :version     version
      :description "Solutions to Matasano's crypto challenges."
      :url         "http://example/FIXME"
      :scm         {:url "https://github.com/yourname/boot-new"}
      :license     {"Eclipse Public License"
                    "http://www.eclipse.org/legal/epl-v10.html"}})

(deftask build
  "Build and install project locally."
  []
  (comp (pom) (jar) (install)))

(require '[adzerk.boot-test :refer [test]])
