import { Injectable } from '@angular/core';
import { DataService, Technique } from './data.service'; //import the DataService component so we can use it

@Injectable()
export class ConfigService {
    public comment_color = "yellow";
    private features = new Map<string, boolean>();
    private featureGroups = new Map<string, string[]>();
    private featureStructure: object[];
    constructor(private dataService: DataService) {
        let self = this;
        dataService.getConfig().subscribe(function(config: any) {
            //parse feature preferences from config json
            config["features"].forEach(function(featureObject: any) {
                self.setFeature_object(featureObject);
            })
            //override json preferences with preferences from URL fragment
            self.getAllFragments().forEach(function(value: string, key: string) {
                let valueBool = (value == 'true');
                if (self.isFeature(key) || self.isFeatureGroup(key)) {
                    // console.log("setting feature", key, valueBool)
                    self.setFeature(key, valueBool);
                }
                // else {
                //     console.log(key, "is not a feature")
                // }
            })
            self.featureStructure = config["features"]
            self.comment_color = config["comment_color"]
        })
    }

    public getFeatureList(): object[] {
        if (!this.featureStructure) return []
        return this.featureStructure;
    }

    public getFeature(featureName: string): boolean {
        return this.features.get(featureName);
    }

    /**
     * Return true if any/all features in the group are enabled
     * @param  featureGroup feature group name
     * @param  type         'any' or 'all' for logical or/and
     * @return              true iffany/all are enabled, false otherwise
     */
    public getFeatureGroup(featureGroup: string, type?: string): boolean {
        if (!this.featureGroups.has(featureGroup)) return true;

        let subFeatures = this.featureGroups.get(featureGroup)
        let count = this.getFeatureGroupCount(featureGroup);
        return type == "any" ? count > 0 : count === subFeatures.length;
    }

    /**
     * Return the number of enabled features in the group
     * @param  featureGroup feature group name
     * @return              the number of enabled features in the group, or -1 if
     *                      the group does not exist
     */
    public getFeatureGroupCount(featureGroup: string): number {
        if (!this.featureGroups.has(featureGroup)) return -1;
        let count = 0
        let subFeatures = this.featureGroups.get(featureGroup)
        for (let i = 0; i < subFeatures.length; i++) {
            if (this.getFeature(subFeatures[i])) count += 1
        }
        return count;
    }

    /**
     * Recursively search an object for boolean properties, set these as features
     * Take a key:value pair of an object. If the value is a boolean, set the
     * feature[key] to value. Otherwise recursively walk value to find boolean
     * options.
     *
     * Additionally, if the given feature grouping (where value is an obj)
     * has been previously defined, boolean properties assigned to the grouping
     * name will apply to all subfeatures of the grouping.
     *
     * @param  featureName string, the fieldname the value was found in
     * @param  value       boolean:object the value of the field. If a boolean,
     *                     sets feature[featureName] = value, otherwise walks recursively
     */
    public setFeature(featureName: string, value: any): string[] {
        let self = this
        // console.log(featureName, value);

        if (typeof(value) == "boolean") { //base case
            if (this.featureGroups.has(featureName)) { //feature group, assign to all subfeatures
                this.featureGroups.get(featureName).forEach(function(subFeatureName: string) {
                    self.setFeature(subFeatureName, value);
                })
            } else { //single feature
                this.features.set(featureName, value);
            }
            return [featureName];
        }

        if (typeof(value) == "object") { //keep walking
            let subfeatures = [];
            Object.keys(value).forEach(function(fieldname: string) {
                subfeatures = Array.prototype.concat(subfeatures, self.setFeature(fieldname, value[fieldname]));
            })
            this.featureGroups.set(featureName, subfeatures);
            return subfeatures;
        }
    }

    /**
     * given a set of feature objects, set the enabledness of that object and all subobjects
     *
     * @param  featureObject {name: string, enabled: boolean, subfeatures?: featureObject[] }
     *                       Of enabled is false and it has subfeatures, they will all be forced to be false too
     * @param  override      Set all subfeatures, and their subfeatures, values to
     *                       this value
     */
    public setFeature_object(featureObject: any, override=null):string[] {
        let self = this

        // base case
        if (!featureObject.hasOwnProperty("subfeatures")) {

            let enabled = override !== null? override : featureObject.enabled
            this.features.set(featureObject.name, enabled)
            return [featureObject.name]
        } else { //has subfeatures
            override = override ? override : !featureObject.enabled ? false : null;
            let subfeatures = [];
            featureObject.subfeatures.forEach(function(subfeature) {
                subfeatures = Array.prototype.concat(subfeatures, self.setFeature_object(subfeature, override))
            })
            this.featureGroups.set(featureObject.name, subfeatures)
            return subfeatures;
        }


    }

    /**
     * Return if the given string corresponds to a defined feature
     * @param  featureName the name of the feature
     * @return             true if the feature exists, false otherwise
     */
    public isFeature(featureName: string): boolean {
        return this.features.has(featureName)
    }
    /**
     * return if the given string corresponds to a defined feature group
     * @param  featureGroupName the name of the feature group
     * @return                  true if it is a feature group, false otherwise
     */
    public isFeatureGroup(featureGroupName: string): boolean {
        return this.featureGroups.has(featureGroupName);
    }

    public getFeatureGroups(): string[] {
        let keys = [];
        this.featureGroups.forEach(function(value, key) { keys.push(key) })
        return keys;
    }

    public getFeatures(): string[] {
        let keys = [];
        this.features.forEach(function(value, key) { keys.push(key) })
        return keys;
    }

    /**
     * Get all url fragments
     * @param  url optional, url to parse instead of window location href
     * @return     all fragments as key-value pairs
     */
    getAllFragments(url?: string): Map<string, string> {
        if (!url) url = window.location.href;
        let fragments = new Map<string, string>();
        let regex = /[#&](\w+)=(\w+)/g

        // let results = url.match(regex)
        var match;
        while (match = regex.exec(url)) {
            fragments.set(match[1], match[2])
        }

        return fragments;
    }

}
